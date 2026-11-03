//! Caller-driven exclusive collector ownership; online refresh is the only grant.
use crate::{
    authority::{HISTORY_BYTES, LiveAuthority},
    *,
};
use contour_core::{
    AdmissionInputs, CaptureScope, MemoryQueue, Observation, OriginWitness, PolicyKeys,
    QueueLimits, QueueStats, RecordDraft, VerifiedPolicy,
};
use std::collections::BTreeSet;
#[path = "stream_capture.rs"]
mod stream_capture;
pub use stream_capture::CaptureId;
#[path = "pool.rs"]
mod pool;
pub use pool::{CollectorPool, PoolCapture};

#[derive(Debug)]
pub enum OwnerError {
    Paused,
    HistoryLimit,
    Queue(QueueError),
    Transport(DeliveryError),
    Retry(RetryError),
}
impl fmt::Display for OwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for OwnerError {}
impl From<QueueError> for OwnerError {
    fn from(e: QueueError) -> Self {
        Self::Queue(e)
    }
}
impl From<DeliveryError> for OwnerError {
    fn from(e: DeliveryError) -> Self {
        Self::Transport(e)
    }
}
impl From<RetryError> for OwnerError {
    fn from(e: RetryError) -> Self {
        Self::Retry(e)
    }
}
#[derive(Debug)]
pub enum SendOutcome {
    Empty,
    Acknowledged {
        receipt_id: String,
        status: ReceiptStatus,
    },
    Deferred(RetryDirective),
}
struct PolicyEntry {
    policy: VerifiedPolicy,
    bytes: usize,
}
struct RetryState {
    controller: RetryController,
    directive: RetryDirective,
    ready: bool,
}
/// No cache bootstrap, shared queue handles, policy setters or exposed authority.
/// Dropping refresh/send futures releases transport and leaves this owner paused.
/// Callers must service expire_retained while paused; this is not a scheduler.
pub struct CollectorOwner {
    client: DeliveryClient,
    keys: PolicyKeys,
    source_ids: Vec<String>,
    queue: MemoryQueue,
    policies: Vec<PolicyEntry>,
    live: Option<LiveAuthority>,
    retry: Option<RetryState>,
    streams: stream_capture::Streams,
    configured_queue_bytes: usize,
    configured_queue_records: usize,
}
impl CollectorOwner {
    pub fn new(
        client: DeliveryClient,
        keys: PolicyKeys,
        source_ids: &[&str],
        limits: QueueLimits,
    ) -> Result<Self, OwnerError> {
        Self::new_version(client, keys, source_ids, limits, WireMode::V1)
    }
    /// Construct an explicit V2 owner; witnesses are untrusted data only.
    pub fn new_v2(
        client: DeliveryClient,
        keys: PolicyKeys,
        source_ids: &[&str],
        limits: QueueLimits,
    ) -> Result<Self, OwnerError> {
        Self::new_version(client, keys, source_ids, limits, WireMode::V2)
    }
    fn new_version(
        client: DeliveryClient,
        keys: PolicyKeys,
        source_ids: &[&str],
        limits: QueueLimits,
        version: WireMode,
    ) -> Result<Self, OwnerError> {
        if client.wire_mode != version {
            return Err(DeliveryError::Configuration.into());
        }
        if source_ids.is_empty()
            || source_ids.len() > 500
            || source_ids.iter().any(|s| !uuid(s))
            || source_ids.iter().copied().collect::<BTreeSet<_>>().len() != source_ids.len()
        {
            return Err(DeliveryError::Configuration.into());
        }
        let queue = if version == WireMode::V2 {
            MemoryQueue::new_v2(client.identity.each_ref().map(String::as_str), limits)?
        } else {
            MemoryQueue::new(client.identity.each_ref().map(String::as_str), limits)?
        };
        Ok(Self {
            client,
            keys,
            source_ids: source_ids.iter().map(|s| (*s).to_owned()).collect(),
            queue,
            policies: Vec::new(),
            live: None,
            retry: None,
            streams: stream_capture::Streams::new()?,
            configured_queue_bytes: limits.byte_limit(),
            configured_queue_records: limits.record_limit(),
        })
    }
    pub fn stats(&self) -> QueueStats {
        self.queue.stats()
    }
    pub fn is_live(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| Instant::now() < live.deadline)
            && self.policies.last().is_some_and(|p| {
                p.policy
                    .validate_capture_at(OffsetDateTime::now_utc())
                    .is_ok()
            })
    }
    fn guard(&mut self) -> Result<(), OwnerError> {
        if !self.is_live() {
            self.live = None;
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        Ok(())
    }
    fn prune_history(&mut self) {
        let retained = self
            .queue
            .retained_policy_revisions()
            .collect::<BTreeSet<_>>();
        let current = self.policies.last().map(|p| p.policy.revision());
        self.policies.retain(|p| {
            Some(p.policy.revision()) == current || retained.contains(&p.policy.revision())
        });
    }
    pub fn expire_retained(&mut self) -> Result<(), OwnerError> {
        self.queue.expire_retained()?;
        self.prune_history();
        if self.queue.stats().records == 0 {
            self.retry = None;
        }
        if !self.is_live() {
            self.live = None;
            self.streams.clear();
        }
        Ok(())
    }
    /// Failure/cancellation cannot extend the old lease. HTTP403 is a pause, not
    /// irreversible queue revocation. History is bounded without forgetting records.
    pub async fn refresh(&mut self) -> Result<(), OwnerError> {
        self.live = None;
        self.streams.clear();
        self.expire_retained()?;
        let fresh = self
            .client
            .refresh_authority(&self.source_ids, &self.keys)
            .await?;
        let same_revision = self
            .policies
            .last()
            .is_some_and(|p| p.policy.revision() == fresh.policy.revision());
        let retained = self
            .queue
            .retained_policy_revisions()
            .collect::<BTreeSet<_>>();
        let needed = |p: &&PolicyEntry| same_revision || retained.contains(&p.policy.revision());
        let bytes: usize = self.policies.iter().filter(needed).map(|p| p.bytes).sum();
        let count = self.policies.iter().filter(needed).count();
        if !same_revision
            && (count >= 500
                || bytes
                    .checked_add(fresh.envelope_bytes)
                    .is_none_or(|n| n > HISTORY_BYTES))
        {
            return Err(OwnerError::HistoryLimit);
        }
        let mut refs = self
            .policies
            .iter()
            .filter(needed)
            .map(|p| &p.policy)
            .collect::<Vec<_>>();
        if !same_revision {
            refs.push(&fresh.policy);
        }
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            &fresh.policy,
            &refs,
            &fresh.live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        // Existing highwater/content checks run even for an otherwise valid reply.
        self.queue.reconcile(&inputs)?;
        if !same_revision {
            self.policies
                .retain(|p| retained.contains(&p.policy.revision()));
            self.policies.push(PolicyEntry {
                policy: fresh.policy,
                bytes: fresh.envelope_bytes,
            });
        }
        self.prune_history();
        if Instant::now() >= fresh.live.deadline {
            return Err(DeliveryError::Deadline.into());
        }
        if self
            .retry
            .as_ref()
            .is_some_and(|r| r.directive == RetryDirective::RenewAuthorizedEnrollment)
        {
            self.retry = None;
        }
        self.live = Some(fresh.live);
        self.guard()
    }
    /// Inspect only under the current live authority. The owner cannot refresh or
    /// revoke concurrently while borrowed; expiry during extraction discards it.
    /// The returned revision is selected by the owner, never by the adapter.
    pub fn inspect_json(
        &mut self,
        scope: &CaptureScope<'_>,
        bytes: &[u8],
    ) -> Result<(u64, Observation), OwnerError> {
        self.inspect_json_inner(scope, bytes, || {})
    }
    // Private hook permits deterministic testing of expiry at the boundary. It
    // cannot be supplied by an adapter and never receives the body or authority.
    fn inspect_json_inner(
        &mut self,
        scope: &CaptureScope<'_>,
        bytes: &[u8],
        after_inspection: impl FnOnce(),
    ) -> Result<(u64, Observation), OwnerError> {
        self.guard()?;
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let result = inputs
            .inspect_json(scope, bytes, OffsetDateTime::now_utc())
            .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        after_inspection();
        self.guard()?;
        Ok(result)
    }
    pub fn admit(&mut self, draft: RecordDraft) -> Result<(), OwnerError> {
        self.admit_inner(draft, None, |_| {})
    }
    // Private fault hook; forwarding adapters cannot supply or access it.
    fn admit_inner(
        &mut self,
        draft: RecordDraft,
        witness: Option<OriginWitness>,
        after_admission: impl FnOnce(&mut Self),
    ) -> Result<(), OwnerError> {
        self.guard()?;
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let admission = match witness {
            Some(w) => self.queue.admit_v2_retractable(draft, w, &inputs)?,
            None => self.queue.admit_retractable(draft, &inputs)?,
        };
        after_admission(self);
        if !self.is_live() {
            self.live = None;
            self.streams.clear();
            self.queue.retract_admission(admission)?;
            return Err(OwnerError::Paused);
        }
        Ok(())
    }
    pub fn freeze(
        &mut self,
        batch_id: &str,
        maximum_records: usize,
        maximum_wire_bytes: usize,
    ) -> Result<bool, OwnerError> {
        self.guard()?;
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let frozen = self
            .queue
            .freeze_with_limits(batch_id, maximum_records, maximum_wire_bytes, &inputs)?
            .is_some();
        if !self.is_live() {
            self.live = None;
        }
        if frozen {
            self.retry = None;
        }
        Ok(frozen)
    }
    /// Outer monotonic authority cap applies in addition to send_once's local
    /// wallclock/attempt deadline. On cancellation all I/O and reservations drop.
    pub async fn send_once(&mut self) -> Result<SendOutcome, OwnerError> {
        self.guard()?;
        self.streams.clear();
        if let Some(retry) = &self.retry {
            if !retry.ready {
                return Ok(SendOutcome::Deferred(retry.directive));
            }
        }
        let live = self.live.take().ok_or(OwnerError::Paused)?;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            refs.last().ok_or(OwnerError::Paused)?,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(QueueError::Admission(e)))?;
        let Some(mut attempt) = self.queue.reserve_delivery(&inputs)? else {
            self.retry = None;
            self.live = Some(live);
            return Ok(SendOutcome::Empty);
        };
        let binding = attempt.view().binding();
        let mut controller = match self.retry.take() {
            Some(retry) if retry.controller.binding() == binding => retry.controller,
            _ => RetryController::for_attempt(&mut attempt),
        };
        let result = timeout_at(live.deadline, self.client.send_once(&mut attempt))
            .await
            .unwrap_or(Err(DeliveryError::Deadline));
        let result = if Instant::now() >= live.deadline
            || self.policies.last().is_none_or(|p| {
                p.policy
                    .validate_capture_at(OffsetDateTime::now_utc())
                    .is_err()
            }) {
            Err(DeliveryError::Deadline)
        } else {
            result
        };
        match result {
            Ok(receipt) => {
                let outcome = SendOutcome::Acknowledged {
                    receipt_id: receipt.receipt_id().to_owned(),
                    status: receipt.status(),
                };
                receipt.acknowledge(attempt)?;
                self.live = Some(live);
                self.prune_history();
                Ok(outcome)
            }
            Err(error) => {
                drop(attempt); // I/O already dropped; release queue before decisions.
                let directive = controller.on_failure(binding, error)?;
                if directive == RetryDirective::DiscardInvalid {
                    self.queue.discard_frozen(binding)?;
                } else {
                    self.retry = Some(RetryState {
                        controller,
                        directive,
                        ready: false,
                    });
                }
                if directive != RetryDirective::RenewAuthorizedEnrollment
                    && Instant::now() < live.deadline
                {
                    self.live = Some(live);
                }
                self.expire_retained()?;
                Ok(SendOutcome::Deferred(directive))
            }
        }
    }
    pub async fn wait_retry(
        &mut self,
        cancel: impl Future<Output = ()>,
    ) -> Result<WaitOutcome, OwnerError> {
        let state = self
            .retry
            .as_mut()
            .ok_or(OwnerError::Retry(RetryError::Stopped))?;
        let outcome = state.controller.wait(cancel).await?;
        state.ready = outcome == WaitOutcome::Ready;
        if outcome == WaitOutcome::Cancelled {
            self.live = None;
        }
        self.expire_retained()?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use contour_core::SourceAssignment;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    fn base64url(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((n >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 63) as usize] as char);
            }
        }
        out
    }
    fn stamp(t: OffsetDateTime) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        )
    }
    pub(super) fn make_owner() -> CollectorOwner {
        make_owner_at(OffsetDateTime::now_utc())
    }
    pub(super) fn make_owner_v2() -> CollectorOwner {
        make_owner_mode_at(WireMode::V2, OffsetDateTime::now_utc(), 60)
    }
    pub(super) fn make_owner_at(now: OffsetDateTime) -> CollectorOwner {
        make_owner_at_with_ttl(now, 60)
    }
    pub(super) fn make_owner_at_with_ttl(now: OffsetDateTime, ttl: u64) -> CollectorOwner {
        make_owner_mode_at(WireMode::V1, now, ttl)
    }
    fn make_owner_mode_at(mode: WireMode, now: OffsetDateTime, ttl: u64) -> CollectorOwner {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let public: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
        let keys = PolicyKeys::new(&[("test", public)]).unwrap();
        let payload = serde_json::to_vec(&json!({"tenant_id":ID,"collector_id":ID,"revision":1,"issued_at":stamp(now - time::Duration::minutes(1)),"expires_at":stamp(now + time::Duration::minutes(1)),"enabled":true,"service_ids":[ID],"techniques":["runtime"],"approved_names":["GET","id"],"denied_templates":[],"inspection_bytes":65536,"depth_limit":32,"queue_bytes":10000,"queue_ttl_seconds":ttl,"durable_queue_enabled":false,"approved_route_segments":["orders"],"parser_profiles":["http_json_v1"]})).unwrap();
        let signature = key.sign(&[b"apicontour/policy/1\n".as_slice(), &payload].concat());
        let envelope = serde_json::to_vec(&json!({"payload_base64url":base64url(&payload),"signature_base64url":base64url(signature.as_ref()),"key_id":"test","signature_profile":"ed25519-v1"})).unwrap();
        let policy = VerifiedPolicy::from_signed_json(&envelope, &keys, ID, ID, now).unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        let client = DeliveryClient {
            host: "localhost".into(),
            address: "127.0.0.1:1".parse().unwrap(),
            identity: [ID.into(), ID.into()],
            tls: TlsConnector::from(Arc::new(config)),
            deadline: Duration::from_secs(1),
            wire_mode: mode,
        };
        let limits = QueueLimits::new(2, 10000).unwrap();
        let mut owner = match mode {
            WireMode::V1 => CollectorOwner::new(client, keys, &[ID], limits),
            WireMode::V2 => CollectorOwner::new_v2(client, keys, &[ID], limits),
        }
        .unwrap();
        owner.policies.push(PolicyEntry {
            policy,
            bytes: envelope.len(),
        });
        owner.live = Some(LiveAuthority {
            sources: vec![
                SourceAssignment::new(ID, [ID; 6], "runtime", &["http_json_v1"]).unwrap(),
            ],
            deadline: Instant::now() + Duration::from_secs(if ttl == 1 { 10 } else { 1 }),
        });
        owner
    }
    pub(super) fn scope() -> CaptureScope<'static> {
        CaptureScope {
            source_id: ID,
            workload: [ID; 4],
            parser_profile: "http_json_v1",
            operation: "GET",
            route_template: "/orders",
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        }
    }
    fn record(owner: &mut CollectorOwner, record_id: &str) -> RecordDraft {
        let (revision, observation) = owner.inspect_json(&scope(), br#"{"id":1}"#).unwrap();
        let seen = contour_core::Timestamp::parse(&stamp(OffsetDateTime::now_utc())).unwrap();
        RecordDraft::from_observation(
            contour_core::RecordMetadata {
                record_id,
                source_id: ID,
                workload: [ID; 4],
                protocol: "http",
                direction: "request",
                visibility: "structure",
                operation: "GET",
                route_template: "/orders",
                route_uncertain: false,
                parser_profile: "http_json_v1",
                policy_revision: revision,
                count: 1,
                first_seen: seen.clone(),
                last_seen: seen,
                sample_numerator: 1,
                sample_denominator: 1,
                status_code: None,
                request_header_names: &[],
                response_header_names: &[],
                query_parameter_names: &[],
            },
            observation,
        )
        .unwrap()
    }
    #[test]
    fn v2_unattributed_stream_is_preserved_and_expiry_clears_on_rejected_start() {
        let mut owner = make_owner_v2();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let id = owner
            .begin_capture_v2(&scope(), &OriginWitness::Unattributed)
            .unwrap();
        owner.capture_fragment(id, br#"{"id":1}"#).unwrap();
        let now = contour_core::Timestamp::parse(&stamp(OffsetDateTime::now_utc())).unwrap();
        let s = scope();
        let metadata = contour_core::RecordMetadata {
            record_id: ID,
            source_id: ID,
            workload: [ID; 4],
            protocol: "http",
            direction: "request",
            visibility: "structure",
            operation: s.operation,
            route_template: s.route_template,
            route_uncertain: false,
            parser_profile: s.parser_profile,
            policy_revision: 1,
            count: 1,
            first_seen: now.clone(),
            last_seen: now,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        owner.finish_and_admit(id, metadata).unwrap();
        assert!(owner.freeze(ID, 1, 10000).unwrap());
        let refs = owner.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            [ID; 2],
            refs[0],
            &refs,
            &owner.live.as_ref().unwrap().sources,
        )
        .unwrap();
        let mut attempt = owner.queue.reserve_delivery(&inputs).unwrap().unwrap();
        let batch = contour_core::BatchV2::from_wire_json(attempt.view().wire()).unwrap();
        assert_eq!(
            batch.records()[0].origin_witness(),
            &OriginWitness::Unattributed
        );
        drop(attempt);
        let id = owner
            .begin_capture_v2(&scope(), &OriginWitness::Unattributed)
            .unwrap();
        owner.capture_fragment(id, b"private").unwrap();
        owner.live.as_mut().unwrap().deadline = Instant::now();
        let invalid = OriginWitness::DownstreamMtlsLeafSha256V1 {
            leaf_sha256: "invalid".into(),
        };
        assert!(owner.begin_capture_v2(&scope(), &invalid).is_err());
        assert!(owner.streams.is_empty());
        assert!(!owner.is_live());
        let mut v1 = make_owner();
        let id = v1.begin_capture(&scope()).unwrap();
        v1.capture_fragment(id, b"private").unwrap();
        v1.live.as_mut().unwrap().deadline = Instant::now();
        assert!(
            v1.begin_capture_v2(&scope(), &OriginWitness::Unattributed)
                .is_err()
        );
        assert!(v1.streams.is_empty());
        assert!(!v1.is_live());
    }
    #[test]
    fn v2_stream_witness_is_bound_through_freeze_and_retry() {
        let mut owner = make_owner_v2();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        assert!(owner.begin_capture(&scope()).is_err());
        let invalid = OriginWitness::DownstreamMtlsLeafSha256V1 {
            leaf_sha256: "A".repeat(64),
        };
        assert!(owner.begin_capture_v2(&scope(), &invalid).is_err());
        let mut witness = OriginWitness::DownstreamMtlsLeafSha256V1 {
            leaf_sha256: "a".repeat(64),
        };
        let id = owner.begin_capture_v2(&scope(), &witness).unwrap();
        witness = OriginWitness::Unattributed;
        owner
            .capture_fragment(id, br#"{"id":1,"password":"secret-marker"}"#)
            .unwrap();
        let now = contour_core::Timestamp::parse(&stamp(OffsetDateTime::now_utc())).unwrap();
        let s = scope();
        let metadata = contour_core::RecordMetadata {
            record_id: ID,
            source_id: ID,
            workload: [ID; 4],
            protocol: "http",
            direction: "request",
            visibility: "structure",
            operation: s.operation,
            route_template: s.route_template,
            route_uncertain: false,
            parser_profile: s.parser_profile,
            policy_revision: 1,
            count: 1,
            first_seen: now.clone(),
            last_seen: now,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        owner.finish_and_admit(id, metadata).unwrap();
        let charge = owner.stats().bytes;
        assert!(owner.freeze(ID, 1, 10000).unwrap());
        assert_eq!(owner.stats().bytes, charge);
        let refs = owner.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            [ID; 2],
            refs[0],
            &refs,
            &owner.live.as_ref().unwrap().sources,
        )
        .unwrap();
        let mut attempt = owner.queue.reserve_delivery(&inputs).unwrap().unwrap();
        assert_eq!(attempt.wire_version(), 2);
        let view = attempt.view();
        let bytes = view.wire().to_vec();
        assert!(bytes.len() * 3 <= charge);
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-marker"));
        let parsed = contour_core::BatchV2::from_wire_json(&bytes).unwrap();
        assert_eq!(
            parsed.records()[0].origin_witness(),
            &OriginWitness::DownstreamMtlsLeafSha256V1 {
                leaf_sha256: "a".repeat(64)
            }
        );
        assert_ne!(parsed.records()[0].origin_witness(), &witness);
        assert_eq!(parsed.request_digest_bytes().unwrap(), *view.digest());
        drop(attempt);
        let mut retry = owner.queue.reserve_delivery(&inputs).unwrap().unwrap();
        assert_eq!(retry.view().wire(), bytes);
        owner.client.wire_mode = WireMode::V1;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(owner.client.send_once(&mut retry)),
            Err(DeliveryError::Configuration)
        ));
    }
    #[test]
    fn expiry_during_copy_preparation_prevents_the_copy_seam() {
        let mut owner = make_owner();
        let id = owner.begin_capture(&scope()).unwrap();
        let mut copied = false;
        let result = owner.capture_fragment_prepared(
            id,
            b"private",
            |owner| {
                owner.live.as_mut().unwrap().deadline = Instant::now();
            },
            || copied = true,
        );
        assert!(matches!(result, Err(OwnerError::Paused)));
        assert!(
            !copied,
            "observational copy occurred after preparation expired authority"
        );
        assert!(owner.streams.is_empty());
    }
    #[test]
    fn raw_capture_tokens_cannot_cross_owner_boundaries() {
        let mut a = make_owner();
        let mut b = make_owner();
        let foreign = a.begin_capture(&scope()).unwrap();
        let own = b.begin_capture(&scope()).unwrap();
        assert!(b.capture_fragment(foreign, b"foreign").is_err());
        b.cancel_capture(foreign);
        b.capture_fragment(own, br#"{"id":1}"#).unwrap();
        assert!(b.finish_capture(own).is_ok());
    }
    #[test]
    fn expiry_during_admission_retracts_only_the_new_record() {
        let mut owner = make_owner();
        owner.queue = MemoryQueue::new([ID; 2], QueueLimits::new(2, 10000).unwrap()).unwrap();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let prior_id = "00000000-0000-4000-8000-000000000002";
        let first = record(&mut owner, prior_id);
        owner.admit(first).unwrap();
        let prior_bytes = owner.stats().bytes;
        let second = record(&mut owner, "00000000-0000-4000-8000-000000000003");
        let result = owner.admit_inner(second, None, |owner| {
            assert_eq!(owner.stats().records, 2);
            owner.live.as_mut().unwrap().deadline = Instant::now();
        });
        assert!(matches!(result, Err(OwnerError::Paused)));
        assert!(!owner.is_live());
        assert_eq!(owner.stats().records, 1);
        assert_eq!(owner.stats().bytes, prior_bytes);
        assert_eq!(
            owner.queue.retained_record_times().next().unwrap().0,
            prior_id
        );
    }
    #[test]
    fn paused_and_expired_owner_reject_before_inspection() {
        let mut owner = make_owner();
        owner.live = None;
        assert!(matches!(
            owner.inspect_json(&scope(), b"0"),
            Err(OwnerError::Paused)
        ));
        let mut owner = make_owner();
        owner.live.as_mut().unwrap().deadline = Instant::now();
        assert!(matches!(
            owner.inspect_json(&scope(), b"0"),
            Err(OwnerError::Paused)
        ));
        assert!(!owner.is_live());
    }
    #[test]
    fn expired_or_wrong_scope_never_copies_a_fragment() {
        let mut owner = make_owner();
        let mut wrong = scope();
        wrong.route_template = "/not-approved";
        assert!(owner.begin_capture(&wrong).is_err());
        let id = owner.begin_capture(&scope()).unwrap();
        owner.live.as_mut().unwrap().deadline = Instant::now();
        let mut copies = 0;
        assert!(
            owner
                .capture_fragment_inner(id, b"secret", || copies += 1)
                .is_err()
        );
        assert_eq!(copies, 0);
        assert!(owner.finish_capture(id).is_err());
    }
    #[test]
    fn fragmented_body_extracts_and_cancel_discards() {
        let mut owner = make_owner();
        let id = owner.begin_capture(&scope()).unwrap();
        owner.capture_fragment(id, br#"{"id":"#).unwrap();
        owner.capture_fragment(id, b"1}").unwrap();
        let (_, observation) = owner.finish_capture(id).unwrap();
        assert_eq!(
            observation.completeness,
            contour_core::Completeness::Complete
        );
        let id = owner.begin_capture(&scope()).unwrap();
        owner.capture_fragment(id, b"123").unwrap();
        owner.cancel_capture(id);
        assert!(owner.finish_capture(id).is_err());
    }
    #[test]
    fn expiry_after_extraction_discards_observation_and_pauses() {
        let mut owner = make_owner();
        let deadline = Instant::now() + Duration::from_millis(100);
        owner.live.as_mut().unwrap().deadline = deadline;
        let result = owner.inspect_json_inner(&scope(), b"0", || {
            while Instant::now() < deadline {
                std::thread::yield_now();
            }
        });
        assert!(matches!(result, Err(OwnerError::Paused)));
        assert!(!owner.is_live());
    }
}
