use crate::{
    Completeness, Kind, Observation, ObservationReason, Shape, Timestamp, UnsignedInteger,
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::fmt;
use std::{collections::HashSet, io, marker::PhantomData};
use time::{Duration, OffsetDateTime};

const MAX_BATCH_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchError {
    Size,
    Invalid,
    Semantic,
    AdmissionTime,
}
impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BatchError {}
pub struct Batch {
    envelope: Envelope,
}
/// Borrowed value-free metadata. Syntax validity does not approve capture or names.
/// Workload order: project, service, environment, deployment. IDs are supplied by
/// the caller; UUID syntax checks do not establish randomness or authenticated identity.
pub struct RecordMetadata<'a> {
    pub record_id: &'a str,
    pub source_id: &'a str,
    pub workload: [&'a str; 4],
    pub protocol: &'a str,
    pub direction: &'a str,
    pub visibility: &'a str,
    pub operation: &'a str,
    pub route_template: &'a str,
    pub route_uncertain: bool,
    pub parser_profile: &'a str,
    pub policy_revision: u64,
    pub count: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub sample_numerator: u64,
    pub sample_denominator: u64,
    pub status_code: Option<u16>,
    pub request_header_names: &'a [&'a str],
    pub response_header_names: &'a [&'a str],
    pub query_parameter_names: &'a [&'a str],
}
/// Checked observation and metadata, without declared queue admission timestamps.
/// A future queue must accept drafts, check policy/source/full metadata approval,
/// reserve capacity, then privately stamp actual queue/expiry times on success.
pub struct RecordDraft {
    pub(crate) record: Record,
}
/// Immutable record with explicitly declared times, not proof of actual enqueue.
pub struct CheckedRecord {
    pub(crate) record: Record,
}
impl fmt::Debug for RecordMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordMetadata")
    }
}
impl fmt::Debug for RecordDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordDraft")
    }
}
impl fmt::Debug for CheckedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedRecord")
    }
}
impl RecordDraft {
    // Conservative per-entry wire charge: timestamp replacements (2*35), comma,
    // and a complete batch envelope (320). Never retained as an extra byte buffer.
    pub(crate) fn retention_charge(&self) -> Result<usize, BatchError> {
        encode(&self.record)?
            .len()
            .checked_add(391)
            .ok_or(BatchError::Size)
    }
    pub fn from_observation(
        metadata: RecordMetadata<'_>,
        observation: Observation,
    ) -> Result<Self, BatchError> {
        // All borrowed strings and list lengths are bounded before any copying.
        if !uuid(metadata.record_id)
            || !uuid(metadata.source_id)
            || metadata.workload.iter().any(|id| !uuid(id))
            || [metadata.protocol, metadata.direction, metadata.visibility]
                .iter()
                .any(|text| text.len() > 16)
            || !string_bound(metadata.operation, 32)
            || !string_bound(metadata.route_template, 256)
            || !profile(metadata.parser_profile)
            || observation.reasons.len() > 8
            || [
                metadata.request_header_names,
                metadata.response_header_names,
                metadata.query_parameter_names,
            ]
            .iter()
            .any(|names| names.len() > 128 || names.iter().any(|name| !string_bound(name, 64)))
        {
            return Err(BatchError::Semantic);
        }
        let reasons = observation
            .reasons
            .iter()
            .map(|reason| {
                match reason {
                    ObservationReason::Limit => "limit",
                    ObservationReason::Permission => "permission",
                    ObservationReason::Malformed => "malformed",
                }
                .to_owned()
            })
            .collect();
        let completeness = match observation.completeness {
            Completeness::Complete => "complete",
            Completeness::Partial => "partial",
            Completeness::Unavailable => "unavailable",
        };
        // These private placeholders permit reuse of the complete wire validator.
        // Drafts cannot be serialized or assembled; both are replaced on declaration.
        let validation_time = metadata.last_seen.clone();
        let record = Record {
            record_id: metadata.record_id.to_owned(),
            source_id: metadata.source_id.to_owned(),
            project_id: metadata.workload[0].to_owned(),
            service_id: metadata.workload[1].to_owned(),
            environment_id: metadata.workload[2].to_owned(),
            deployment_id: metadata.workload[3].to_owned(),
            protocol: metadata.protocol.to_owned(),
            direction: metadata.direction.to_owned(),
            visibility: metadata.visibility.to_owned(),
            operation: metadata.operation.to_owned(),
            route_template: metadata.route_template.to_owned(),
            route_uncertain: metadata.route_uncertain,
            parser_profile: metadata.parser_profile.to_owned(),
            policy_revision: UnsignedInteger::new(metadata.policy_revision),
            completeness: completeness.to_owned(),
            reasons: Bounded(reasons),
            structure: WireShape(observation.shape),
            count: UnsignedInteger::new(metadata.count),
            first_seen: metadata.first_seen,
            last_seen: metadata.last_seen,
            sample_numerator: UnsignedInteger::new(metadata.sample_numerator),
            sample_denominator: UnsignedInteger::new(metadata.sample_denominator),
            status_code: metadata
                .status_code
                .map(|status| UnsignedInteger::new(u64::from(status))),
            request_header_names: Bounded(
                metadata
                    .request_header_names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            ),
            response_header_names: Bounded(
                metadata
                    .response_header_names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            ),
            query_parameter_names: Bounded(
                metadata
                    .query_parameter_names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            ),
            queued_at: validation_time.clone(),
            expires_at: validation_time,
        };
        record.validate(record.last_seen.instant())?;
        Ok(Self { record })
    }
    /// Pure declared-time construction. This does not reserve capacity or enqueue.
    pub fn declare_queue_times(
        mut self,
        queued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<CheckedRecord, BatchError> {
        self.record.queued_at = queued_at;
        self.record.expires_at = expires_at;
        self.record.validate(self.record.queued_at.instant())?;
        Ok(CheckedRecord {
            record: self.record,
        })
    }
}
impl CheckedRecord {
    pub fn queued_at(&self) -> &Timestamp {
        &self.record.queued_at
    }
    pub fn expires_at(&self) -> &Timestamp {
        &self.record.expires_at
    }
}
/// Minimal immutable authority lookup projection from an already checked batch.
pub struct AuthorityRequest<'a> {
    source_id: &'a str,
    revision: u64,
    queued_at: OffsetDateTime,
}
impl AuthorityRequest<'_> {
    pub fn source_id(&self) -> &str {
        self.source_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn queued_at(&self) -> OffsetDateTime {
        self.queued_at
    }
}
impl fmt::Debug for Batch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Batch")
    }
}
impl Batch {
    /// Assemble syntax-checked records. Actual policy admission is still mandatory.
    pub fn assemble(
        batch_id: &str,
        identity: [&str; 2],
        created_at: Timestamp,
        records: Vec<CheckedRecord>,
    ) -> Result<Self, BatchError> {
        if records.is_empty()
            || records.len() > 500
            || !uuid(batch_id)
            || identity.iter().any(|id| !uuid(id))
        {
            return Err(BatchError::Semantic);
        }
        let envelope = Envelope {
            wire_version: UnsignedInteger::new(1),
            batch_id: batch_id.to_owned(),
            tenant_id: identity[0].to_owned(),
            collector_id: identity[1].to_owned(),
            created_at,
            records: Bounded(records.into_iter().map(|record| record.record).collect()),
        };
        envelope.validate()?;
        let batch = Self { envelope };
        batch.to_wire_json()?;
        Ok(batch)
    }
    /// Check wire syntax and consistency; names and identities still need policy authorization.
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(BatchError::Size);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        envelope.validate()?;
        let batch = Self { envelope };
        batch.to_wire_json()?;
        Ok(batch)
    }
    pub fn to_wire_json(&self) -> Result<Vec<u8>, BatchError> {
        encode(&self.envelope)
    }
    pub fn request_digest(&self) -> Result<String, BatchError> {
        let digest: sha2::digest::Output<Sha256> = self.request_digest_bytes()?.into();
        Ok(format!("{digest:x}"))
    }
    /// Exact domain-separated digest bytes for persistence; same format as the hex API.
    pub fn request_digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        request_digest(&self.envelope)
    }
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), BatchError> {
        let age = self.envelope.created_at.instant() - now;
        if age < -Duration::hours(24) - Duration::minutes(5)
            || age > Duration::minutes(5)
            || self
                .envelope
                .records
                .0
                .iter()
                .any(|record| record.expires_at.instant() <= now)
        {
            return Err(BatchError::AdmissionTime);
        }
        Ok(())
    }
    pub fn batch_id(&self) -> &str {
        &self.envelope.batch_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.envelope.tenant_id
    }
    pub fn collector_id(&self) -> &str {
        &self.envelope.collector_id
    }
    pub fn record_count(&self) -> usize {
        self.envelope.records.0.len()
    }
    pub fn authority_requests(&self) -> impl ExactSizeIterator<Item = AuthorityRequest<'_>> {
        self.envelope
            .records
            .0
            .iter()
            .map(|record| AuthorityRequest {
                source_id: &record.source_id,
                revision: record.policy_revision.get(),
                queued_at: record.queued_at.instant(),
            })
    }
    /// Checked syntax only. Persist projections only after trusted inbox integrity
    /// and scope validation. Deployment/source evidence never changes the key.
    pub fn operation_observations(
        &self,
    ) -> impl ExactSizeIterator<Item = crate::OperationObservation<'_>> {
        self.envelope
            .records
            .0
            .iter()
            .map(|record| crate::OperationObservation {
                key: crate::OperationKey {
                    components: [
                        self.tenant_id(),
                        &record.project_id,
                        &record.service_id,
                        &record.environment_id,
                        &record.protocol,
                        &record.direction,
                        &record.operation,
                        &record.route_template,
                    ],
                },
                deployment_id: &record.deployment_id,
                collector_id: self.collector_id(),
                source_id: &record.source_id,
                parser_profile: &record.parser_profile,
                policy_revision: record.policy_revision.get(),
                visibility: &record.visibility,
                route_uncertain: record.route_uncertain,
                record_id: &record.record_id,
                canonicalization_version: 1,
                structure: &record.structure.0,
                completeness: &record.completeness,
                reasons: &record.reasons.0,
                count: record.count.get(),
                first_seen: &record.first_seen,
                last_seen: &record.last_seen,
                sample_numerator: record.sample_numerator.get(),
                sample_denominator: record.sample_denominator.get(),
                status_code: record.status_code.map(|status| status.get()),
                request_header_names: &record.request_header_names.0,
                response_header_names: &record.response_header_names.0,
                query_parameter_names: &record.query_parameter_names.0,
                queued_at: &record.queued_at,
                expires_at: &record.expires_at,
            })
    }
    pub(crate) fn records(&self) -> &[Record] {
        &self.envelope.records.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    wire_version: UnsignedInteger,
    batch_id: String,
    tenant_id: String,
    collector_id: String,
    created_at: Timestamp,
    records: Bounded<Record, 500>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    record_id: String,
    pub(crate) project_id: String,
    pub(crate) service_id: String,
    pub(crate) environment_id: String,
    pub(crate) deployment_id: String,
    protocol: String,
    direction: String,
    pub(crate) operation: String,
    pub(crate) route_template: String,
    route_uncertain: bool,
    pub(crate) parser_profile: String,
    pub(crate) policy_revision: UnsignedInteger,
    visibility: String,
    completeness: String,
    reasons: Bounded<String, 8>,
    pub(crate) structure: WireShape,
    count: UnsignedInteger,
    first_seen: Timestamp,
    last_seen: Timestamp,
    sample_numerator: UnsignedInteger,
    sample_denominator: UnsignedInteger,
    #[serde(deserialize_with = "nullable_status")]
    status_code: Option<UnsignedInteger>,
    pub(crate) source_id: String,
    pub(crate) request_header_names: Bounded<String, 128>,
    pub(crate) response_header_names: Bounded<String, 128>,
    pub(crate) query_parameter_names: Bounded<String, 128>,
    pub(crate) queued_at: Timestamp,
    pub(crate) expires_at: Timestamp,
}

fn nullable_status<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Option<UnsignedInteger>, D::Error> {
    Option::<UnsignedInteger>::deserialize(decoder)
}

impl Envelope {
    fn validate(&self) -> Result<(), BatchError> {
        if self.wire_version.get() != 1
            || self.records.0.is_empty()
            || [&self.batch_id, &self.tenant_id, &self.collector_id]
                .iter()
                .any(|id| !uuid(id))
        {
            return Err(BatchError::Semantic);
        }
        let mut ids = HashSet::new();
        for record in &self.records.0 {
            if !ids.insert(&record.record_id) {
                return Err(BatchError::Semantic);
            }
            record.validate(self.created_at.instant())?;
        }
        Ok(())
    }
}

impl Record {
    pub(crate) fn record_id(&self) -> &str {
        &self.record_id
    }
    fn validate(&self, created: OffsetDateTime) -> Result<(), BatchError> {
        let reasons = &self.reasons.0;
        if [
            &self.record_id,
            &self.project_id,
            &self.service_id,
            &self.environment_id,
            &self.deployment_id,
            &self.source_id,
        ]
        .iter()
        .any(|id| !uuid(id))
            || !valid_operation(
                &self.protocol,
                &self.direction,
                &self.operation,
                &self.route_template,
            )
            || !["structure", "operation", "connection"].contains(&self.visibility.as_str())
            || !["complete", "partial", "unavailable"].contains(&self.completeness.as_str())
            || !profile(&self.parser_profile)
            || self.policy_revision.get() == 0
            || !(1..=1_000_000_000).contains(&self.count.get())
            || !(1..=1_000_000).contains(&self.sample_numerator.get())
            || !(1..=1_000_000).contains(&self.sample_denominator.get())
            || self.sample_numerator > self.sample_denominator
            || self
                .status_code
                .is_some_and(|status| !(100..=599).contains(&status.get()))
            || !unique(reasons)
            || reasons.iter().any(|reason| {
                ![
                    "permission",
                    "encrypted",
                    "unsupported",
                    "sampled",
                    "limit",
                    "malformed",
                    "source_gap",
                    "clock_skew",
                ]
                .contains(&reason.as_str())
            })
            || [
                &self.request_header_names.0,
                &self.response_header_names.0,
                &self.query_parameter_names.0,
            ]
            .iter()
            .any(|names| !unique(names) || names.iter().any(|name| !string_bound(name, 64)))
        {
            return Err(BatchError::Semantic);
        }
        let inconsistent_evidence = if self.completeness == "complete" {
            incomplete(&self.structure.0)
                || reasons.iter().any(|reason| {
                    [
                        "permission",
                        "encrypted",
                        "unsupported",
                        "limit",
                        "malformed",
                        "source_gap",
                    ]
                    .contains(&reason.as_str())
                })
        } else {
            reasons.is_empty()
        };
        if inconsistent_evidence
            || (self.visibility != "structure" && self.structure.0.kind() != Kind::Unknown)
            || self.first_seen.instant() > self.last_seen.instant()
            || self.queued_at.instant() > created
            || self.expires_at.instant() < created
        {
            return Err(BatchError::Semantic);
        }
        let lifetime = self.expires_at.instant() - self.queued_at.instant();
        if lifetime < Duration::ZERO || lifetime > Duration::hours(24) {
            return Err(BatchError::Semantic);
        }
        self.structure
            .0
            .to_wire_json()
            .map_err(|_| BatchError::Size)?;
        Ok(())
    }
}

pub(crate) fn valid_operation(
    protocol: &str,
    direction: &str,
    operation: &str,
    template: &str,
) -> bool {
    [
        "http",
        "graphql",
        "grpc",
        "websocket",
        "kafka",
        "mqtt",
        "cloud",
    ]
    .contains(&protocol)
        && [
            "request",
            "response",
            "publish",
            "consume",
            "operation",
            "connection",
        ]
        .contains(&direction)
        && string_bound(operation, 32)
        && string_bound(template, 256)
        && !template.contains(['?', '#'])
}

pub(crate) fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn string_bound(text: &str, max: usize) -> bool {
    !text.is_empty() && text.chars().take(max + 1).count() <= max
}
fn profile(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().enumerate().all(|(i, byte)| {
            byte.is_ascii_alphabetic()
                || byte == b'_'
                || (i > 0 && (byte.is_ascii_digit() || matches!(byte, b'.' | b'-')))
        })
}
fn unique(values: &[String]) -> bool {
    values.iter().collect::<HashSet<_>>().len() == values.len()
}

fn incomplete(shape: &Shape) -> bool {
    match &shape.node {
        crate::Node::Unknown(reason) => *reason != crate::UnknownReason::Empty,
        crate::Node::Object(fields, additional) => {
            fields.iter().any(|(_, child)| incomplete(child))
                || additional.as_deref().is_some_and(incomplete)
        }
        crate::Node::Array(items) => incomplete(items),
        crate::Node::Union(children) => children.iter().any(incomplete),
        crate::Node::Primitive(_) => false,
    }
}

pub(crate) struct WireShape(pub(crate) Shape);
impl<'de> Deserialize<'de> for WireShape {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let raw = <&RawValue>::deserialize(decoder)?;
        Shape::from_wire_json(raw.get().as_bytes())
            .map(Self)
            .map_err(|_| de::Error::custom("invalid structure"))
    }
}
impl Serialize for WireShape {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct Bounded<T, const N: usize>(pub(crate) Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct List<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for List<T, N> {
            type Value = Bounded<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded list")
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let mut values = Vec::new();
                loop {
                    if values.len() == N {
                        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                            return Err(de::Error::custom("list limit"));
                        }
                        break;
                    }
                    match sequence.next_element()? {
                        Some(value) => values.push(value),
                        None => break,
                    }
                }
                Ok(Bounded(values))
            }
        }
        decoder.deserialize_seq(List::<T, N>(PhantomData))
    }
}

struct Output(Vec<u8>);
impl io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BATCH_BYTES - self.0.len() {
            return Err(io::Error::other("batch size"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, BatchError> {
    let mut output = Output(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|_| BatchError::Size)?;
    Ok(output.0)
}
fn request_digest(value: &impl Serialize) -> Result<[u8; 32], BatchError> {
    let mut value = serde_json::to_value(value).map_err(|_| BatchError::Invalid)?;
    value.sort_all_objects();
    let bytes = encode(&value)?;
    let mut digest = Sha256::new();
    digest.update(b"apicontour/batch/1\n");
    digest.update(bytes);
    Ok(digest.finalize().into())
}
#[derive(Serialize)]
pub(crate) struct BorrowedBatch<'a> {
    wire_version: UnsignedInteger,
    batch_id: &'a str,
    tenant_id: &'a str,
    collector_id: &'a str,
    created_at: &'a Timestamp,
    records: &'a [&'a Record],
}
impl<'a> BorrowedBatch<'a> {
    pub(crate) fn new(
        batch_id: &'a str,
        identity: [&'a str; 2],
        created_at: &'a Timestamp,
        records: &'a [&'a Record],
    ) -> Result<Self, BatchError> {
        if !uuid(batch_id)
            || identity.iter().any(|id| !uuid(id))
            || records.is_empty()
            || records.len() > 500
        {
            return Err(BatchError::Semantic);
        }
        let mut ids = HashSet::new();
        for record in records {
            if !ids.insert(record.record_id()) {
                return Err(BatchError::Semantic);
            }
            record.validate(created_at.instant())?;
        }
        Ok(Self {
            wire_version: UnsignedInteger::new(1),
            batch_id,
            tenant_id: identity[0],
            collector_id: identity[1],
            created_at,
            records,
        })
    }
    pub(crate) fn length(&self) -> Result<usize, BatchError> {
        let mut counter = Count(0);
        serde_json::to_writer(&mut counter, self).map_err(|_| BatchError::Size)?;
        Ok(counter.0)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, BatchError> {
        encode(self)
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32], BatchError> {
        request_digest(self)
    }
}
struct Count(usize);
impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BATCH_BYTES - self.0 {
            return Err(io::Error::other("batch size"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
