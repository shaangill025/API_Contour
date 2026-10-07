use crate::{Kind, Shape, Timestamp, UnsignedInteger};
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
        let mut value = serde_json::to_value(&self.envelope).map_err(|_| BatchError::Invalid)?;
        value.sort_all_objects();
        let bytes = encode(&value)?;
        let mut digest = Sha256::new();
        digest.update(b"apicontour/batch/1\n");
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
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
            || ![
                "http",
                "graphql",
                "grpc",
                "websocket",
                "kafka",
                "mqtt",
                "cloud",
            ]
            .contains(&self.protocol.as_str())
            || ![
                "request",
                "response",
                "publish",
                "consume",
                "operation",
                "connection",
            ]
            .contains(&self.direction.as_str())
            || !["structure", "operation", "connection"].contains(&self.visibility.as_str())
            || !["complete", "partial", "unavailable"].contains(&self.completeness.as_str())
            || !string_bound(&self.operation, 32)
            || !string_bound(&self.route_template, 256)
            || self.route_template.contains(['?', '#'])
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

fn uuid(text: &str) -> bool {
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
