//! Owner-private bounded raw fragments. No payload leaves this module except
//! through the existing signed structural extractor.
use super::{CollectorOwner, OwnerError};
use contour_core::{
    AdmissionInputs, CaptureScope, Completeness, Observation, ObservationReason, OriginWitness,
    RecordDraft, RecordMetadata, Shape, UnknownReason,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
use time::OffsetDateTime;
use zeroize::Zeroize;

const MAX_STREAMS: usize = 16;
const MAX_RAW: usize = 1024 * 1024;
const MAX_BODY: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureId {
    owner: u64,
    sequence: u64,
}
impl CaptureId {
    pub(super) fn sequence(self) -> u64 {
        self.sequence
    }
}
struct Stream {
    source: String,
    workload: [String; 4],
    profile: String,
    operation: String,
    route: String,
    bytes: Vec<u8>,
    limited: bool,
    witness: Option<OriginWitness>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl Stream {
    fn scope(&self) -> CaptureScope<'_> {
        CaptureScope {
            source_id: &self.source,
            workload: self.workload.each_ref().map(String::as_str),
            parser_profile: &self.profile,
            operation: &self.operation,
            route_template: &self.route,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        }
    }
}
pub(crate) struct Streams {
    instance: u64,
    next: u64,
    total: usize,
    entries: BTreeMap<CaptureId, Stream>,
}
impl Streams {
    pub(crate) fn new() -> Result<Self, OwnerError> {
        static NEXT_STREAM_OWNER: AtomicU64 = AtomicU64::new(1);
        let instance = NEXT_STREAM_OWNER
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| OwnerError::Paused)?;
        Ok(Self {
            instance,
            next: 0,
            total: 0,
            entries: BTreeMap::new(),
        })
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn cancel_through(&mut self, sequence: u64) {
        self.entries.retain(|id, _| id.sequence > sequence);
        self.total = self.entries.values().map(|entry| entry.bytes.len()).sum();
    }
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }
    fn remove(&mut self, id: CaptureId) -> Option<Stream> {
        let stream = self.entries.remove(&id)?;
        self.total = self.total.saturating_sub(stream.bytes.len());
        Some(stream)
    }
}
impl CollectorOwner {
    /// Reserve a private stream under the current live scope. The returned token
    /// identifies storage only; it does not confer authority on later calls.
    pub fn begin_capture(&mut self, scope: &CaptureScope<'_>) -> Result<CaptureId, OwnerError> {
        self.begin_capture_version(scope, None)
    }
    /// Reserve a V2 stream with an immutable, untrusted witness claim.
    pub fn begin_capture_v2(
        &mut self,
        scope: &CaptureScope<'_>,
        witness: &OriginWitness,
    ) -> Result<CaptureId, OwnerError> {
        self.guard()?;
        if self.client.wire_mode != super::WireMode::V2 {
            return Err(OwnerError::Paused);
        }
        let witness = match witness {
            OriginWitness::Unattributed => OriginWitness::Unattributed,
            OriginWitness::DownstreamMtlsLeafSha256V1 { leaf_sha256 }
                if leaf_sha256.len() == 64
                    && leaf_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                OriginWitness::DownstreamMtlsLeafSha256V1 {
                    leaf_sha256: leaf_sha256.clone(),
                }
            }
            _ => return Err(OwnerError::Paused),
        };
        self.begin_capture_version(scope, Some(witness))
    }
    fn begin_capture_version(
        &mut self,
        scope: &CaptureScope<'_>,
        witness: Option<OriginWitness>,
    ) -> Result<CaptureId, OwnerError> {
        self.guard()?;
        if (self.client.wire_mode == super::WireMode::V2) != witness.is_some() {
            return Err(OwnerError::Paused);
        }
        if !scope.request_header_names.is_empty()
            || !scope.response_header_names.is_empty()
            || !scope.query_parameter_names.is_empty()
            || self.streams.entries.len() >= MAX_STREAMS
        {
            return Err(OwnerError::Paused);
        }
        let limit = self.check_stream_scope(scope)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| OwnerError::Paused)?;
        self.guard()?;
        self.streams.next = self.streams.next.checked_add(1).ok_or(OwnerError::Paused)?;
        let id = CaptureId {
            owner: self.streams.instance,
            sequence: self.streams.next,
        };
        self.streams.entries.insert(
            id,
            Stream {
                source: scope.source_id.to_owned(),
                workload: scope.workload.map(str::to_owned),
                profile: scope.parser_profile.to_owned(),
                operation: scope.operation.to_owned(),
                route: scope.route_template.to_owned(),
                bytes,
                limited: false,
                witness,
            },
        );
        Ok(id)
    }
    fn check_stream_scope(&self, scope: &CaptureScope<'_>) -> Result<usize, OwnerError> {
        let live = self.live.as_ref().ok_or(OwnerError::Paused)?;
        let current = &self.policies.last().ok_or(OwnerError::Paused)?.policy;
        let refs = self.policies.iter().map(|p| &p.policy).collect::<Vec<_>>();
        let inputs = AdmissionInputs::new(
            self.client.identity.each_ref().map(String::as_str),
            current,
            &refs,
            &live.sources,
        )
        .map_err(|e| OwnerError::Queue(crate::QueueError::Admission(e)))?;
        inputs
            .check_capture_scope(scope, OffsetDateTime::now_utc())
            .map_err(|e| OwnerError::Queue(crate::QueueError::Admission(e)))?;
        Ok(current.inspection_bytes().min(MAX_BODY))
    }
    /// Copy only while the owner holds a current scoped grant. The source slice
    /// is the unmodified application frame; it is never retained or cloned.
    pub fn capture_fragment(&mut self, id: CaptureId, bytes: &[u8]) -> Result<(), OwnerError> {
        self.capture_fragment_inner(id, bytes, || {})
    }
    pub(super) fn capture_fragment_inner(
        &mut self,
        id: CaptureId,
        bytes: &[u8],
        before_copy: impl FnOnce(),
    ) -> Result<(), OwnerError> {
        self.capture_fragment_prepared(id, bytes, |_| {}, before_copy)
    }
    // Private deterministic preparation seam; adapters cannot alter authority.
    pub(super) fn capture_fragment_prepared(
        &mut self,
        id: CaptureId,
        bytes: &[u8],
        prepared: impl FnOnce(&mut Self),
        before_copy: impl FnOnce(),
    ) -> Result<(), OwnerError> {
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        let stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        let limit = self.check_stream_scope(&stream.scope())?;
        let mut stream = stream;
        if stream.limited {
            self.guard()?;
            self.streams.entries.insert(id, stream);
            return Ok(());
        }
        if bytes.len() > limit.saturating_sub(stream.bytes.len()) {
            // The inspected prefix is no longer useful. Wipe it immediately and
            // retain only a typed limit marker, never the overflowing fragment.
            stream.bytes.zeroize();
            stream.bytes = Vec::new();
            stream.limited = true;
            self.guard()?;
            self.streams.entries.insert(id, stream);
            return Ok(());
        }
        // Only fragments that will be retained consume the aggregate budget.
        if bytes.len() > MAX_RAW.saturating_sub(self.streams.total + stream.bytes.len()) {
            return Err(OwnerError::Paused);
        }
        stream
            .bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| OwnerError::Paused)?;
        prepared(self);
        self.guard()?;
        before_copy();
        stream.bytes.extend_from_slice(bytes);
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        self.streams.total += stream.bytes.len();
        self.streams.entries.insert(id, stream);
        Ok(())
    }
    pub fn cancel_capture(&mut self, id: CaptureId) {
        self.streams.remove(id);
    }
    pub fn finish_capture(&mut self, id: CaptureId) -> Result<(u64, Observation), OwnerError> {
        if self.guard().is_err() {
            self.streams.clear();
            return Err(OwnerError::Paused);
        }
        let stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        self.inspect_stream(&stream)
    }
    fn inspect_stream(&mut self, stream: &Stream) -> Result<(u64, Observation), OwnerError> {
        if !stream.limited {
            return self.inspect_json(&stream.scope(), &stream.bytes);
        }
        // Validate current scope and policy even though no body bytes remain.
        self.guard()?;
        self.check_stream_scope(&stream.scope())?;
        let revision = self
            .policies
            .last()
            .ok_or(OwnerError::Paused)?
            .policy
            .revision();
        self.guard()?;
        Ok((
            revision,
            Observation {
                shape: Shape::unknown(UnknownReason::Limit),
                completeness: Completeness::Partial,
                reasons: vec![ObservationReason::Limit],
            },
        ))
    }
    pub(super) fn finish_and_admit(
        &mut self,
        id: CaptureId,
        mut metadata: RecordMetadata<'_>,
    ) -> Result<(), OwnerError> {
        self.guard()?;
        let mut stream = self.streams.remove(id).ok_or(OwnerError::Paused)?;
        if metadata.source_id != stream.source
            || metadata.workload != stream.workload.each_ref().map(String::as_str)
            || metadata.parser_profile != stream.profile
            || metadata.operation != stream.operation
            || metadata.route_template != stream.route
            || !metadata.request_header_names.is_empty()
            || !metadata.response_header_names.is_empty()
            || !metadata.query_parameter_names.is_empty()
        {
            return Err(OwnerError::Paused);
        }
        let (revision, observation) = self.inspect_stream(&stream)?;
        metadata.policy_revision = revision;
        let draft =
            RecordDraft::from_observation(metadata, observation).map_err(|_| OwnerError::Paused)?;
        let witness = stream.witness.take();
        self.admit_inner(draft, witness, |_| {})
    }
}

#[cfg(test)]
mod tests {
    use super::super::capture_tests::{make_owner, scope};
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn overflow_discards_raw_and_ignores_later_bytes_but_rechecks_authority() {
        let mut owner = make_owner();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let id = owner.begin_capture(&scope()).unwrap();
        owner.capture_fragment(id, b"sensitive-prefix").unwrap();
        owner.capture_fragment(id, &vec![b'x'; MAX_BODY]).unwrap();
        let stream = owner.streams.entries.get(&id).unwrap();
        assert!(stream.limited);
        assert!(stream.bytes.is_empty());
        assert_eq!(stream.bytes.capacity(), 0);
        assert_eq!(owner.streams.total, 0);
        owner
            .capture_fragment(id, &vec![b'y'; MAX_RAW + 1])
            .unwrap();
        assert_eq!(owner.streams.entries.get(&id).unwrap().bytes.capacity(), 0);
        owner.live.as_mut().unwrap().deadline = Instant::now();
        assert!(owner.capture_fragment(id, b"later").is_err());
        assert!(owner.streams.is_empty());
    }

    #[test]
    fn limited_stream_rechecks_changed_scope_before_finish() {
        let mut owner = make_owner();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let id = owner.begin_capture(&scope()).unwrap();
        owner
            .capture_fragment(id, &vec![b'x'; MAX_BODY + 1])
            .unwrap();
        owner.live.as_mut().unwrap().sources.clear();
        assert!(owner.finish_capture(id).is_err());
        assert!(owner.streams.is_empty());
    }

    #[test]
    fn aggregate_raw_guard_rejects_a_within_limit_fragment_when_forced_full() {
        let mut owner = make_owner();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let id = owner.begin_capture(&scope()).unwrap();
        owner.capture_fragment(id, b"x").unwrap();
        owner.streams.total = MAX_RAW;
        assert!(owner.capture_fragment(id, b"y").is_err());
        assert!(!owner.streams.entries.contains_key(&id));
    }

    #[test]
    fn oversized_single_frame_and_fragmented_body_have_identical_limit_result() {
        let mut owner = make_owner();
        owner.live.as_mut().unwrap().deadline = Instant::now() + Duration::from_secs(10);
        let large = vec![b'x'; MAX_RAW + 1];
        let first = owner.begin_capture(&scope()).unwrap();
        let second = owner.begin_capture(&scope()).unwrap();
        owner.capture_fragment(first, &large).unwrap();
        for chunk in large.chunks(MAX_BODY) {
            owner.capture_fragment(second, chunk).unwrap();
        }
        for id in [first, second] {
            let stream = owner.streams.entries.get(&id).unwrap();
            assert!(stream.limited);
            assert_eq!(stream.bytes.capacity(), 0);
        }
        assert_eq!(owner.streams.total, 0);
        let (a_revision, a) = owner.finish_capture(first).unwrap();
        let (b_revision, b) = owner.finish_capture(second).unwrap();
        assert_eq!(a_revision, b_revision);
        assert_eq!(a.shape, b.shape);
        assert_eq!(a.completeness, b.completeness);
        assert_eq!(a.reasons, b.reasons);
        assert_eq!(a.shape, Shape::unknown(UnknownReason::Limit));
        assert_eq!(a.completeness, Completeness::Partial);
        assert_eq!(a.reasons, vec![ObservationReason::Limit]);
    }
}
