//! Strict data-only batch V2 decoding. An origin witness is an untrusted claim:
//! it grants no transport, workload, lifecycle, or capture authority.
use crate::{
    BatchError, Timestamp, UnsignedInteger,
    batch::{self, Bounded, Record},
};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::{collections::HashSet, fmt};

/// A syntactically checked batch, not proof of authentication or admission.
pub struct BatchV2 {
    envelope: EnvelopeV2,
}

/// One immutable V1-format record with a required, untrusted witness.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchV2Record {
    record: Record,
    origin_witness: OriginWitness,
}

/// Claimed origin evidence only. Neither variant establishes an identity.
#[derive(Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum OriginWitness {
    #[serde(rename = "downstream_mtls_leaf_sha256_v1")]
    DownstreamMtlsLeafSha256V1 { leaf_sha256: String },
    #[serde(rename = "unattributed")]
    Unattributed,
}
impl<'de> Deserialize<'de> for OriginWitness {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            #[serde(default, deserialize_with = "present_string")]
            leaf_sha256: Option<String>,
        }
        fn present_string<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<String>, D::Error> {
            String::deserialize(deserializer).map(Some)
        }
        let wire = Wire::deserialize(deserializer)?;
        match (wire.kind.as_str(), wire.leaf_sha256) {
            ("unattributed", None) => Ok(Self::Unattributed),
            ("downstream_mtls_leaf_sha256_v1", Some(leaf_sha256)) => {
                Ok(Self::DownstreamMtlsLeafSha256V1 { leaf_sha256 })
            }
            _ => Err(de::Error::custom("invalid origin witness")),
        }
    }
}
impl fmt::Debug for OriginWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginWitness")
    }
}
impl fmt::Debug for BatchV2Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BatchV2Record")
    }
}
impl fmt::Debug for BatchV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BatchV2")
    }
}
impl OriginWitness {
    fn validate(&self) -> Result<(), BatchError> {
        match self {
            Self::Unattributed => Ok(()),
            Self::DownstreamMtlsLeafSha256V1 { leaf_sha256 }
                if leaf_sha256.len() == 64
                    && leaf_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Ok(())
            }
            _ => Err(BatchError::Semantic),
        }
    }
}
impl BatchV2Record {
    pub fn record_id(&self) -> &str {
        self.record.record_id()
    }
    pub fn source_id(&self) -> &str {
        &self.record.source_id
    }
    /// Project, service, environment and deployment from the legacy record;
    /// these are destination scope claims, not origin authentication.
    pub fn workload(&self) -> [&str; 4] {
        [
            &self.record.project_id,
            &self.record.service_id,
            &self.record.environment_id,
            &self.record.deployment_id,
        ]
    }
    pub fn origin_witness(&self) -> &OriginWitness {
        &self.origin_witness
    }
    /// Serialize the existing checked V1 record, without its V2 wrapper.
    pub fn record_wire_json(&self) -> Result<Vec<u8>, BatchError> {
        batch::encode(&self.record)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeV2 {
    wire_version: UnsignedInteger,
    batch_id: String,
    tenant_id: String,
    collector_id: String,
    created_at: Timestamp,
    records: Bounded<BatchV2Record, 500>,
}
impl BatchV2 {
    /// Bounded strict syntax and V1 record consistency only; no authorization.
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > batch::MAX_BATCH_BYTES {
            return Err(BatchError::Size);
        }
        let envelope: EnvelopeV2 =
            serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        if envelope.wire_version.get() != 2
            || envelope.records.0.is_empty()
            || [
                &envelope.batch_id,
                &envelope.tenant_id,
                &envelope.collector_id,
            ]
            .iter()
            .any(|id| !batch::uuid(id))
        {
            return Err(BatchError::Semantic);
        }
        let mut ids = HashSet::new();
        for wrapper in &envelope.records.0 {
            if !ids.insert(wrapper.record.record_id()) {
                return Err(BatchError::Semantic);
            }
            wrapper.origin_witness.validate()?;
            wrapper.record.validate(envelope.created_at.instant())?;
        }
        let result = Self { envelope };
        result.to_wire_json()?;
        Ok(result)
    }
    pub fn to_wire_json(&self) -> Result<Vec<u8>, BatchError> {
        batch::encode(&self.envelope)
    }
    /// SHA-256 of the entire canonical V2 envelope, using its distinct domain.
    pub fn request_digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.envelope, b"apicontour/batch/2\n")
    }
    pub fn request_digest(&self) -> Result<String, BatchError> {
        use sha2::Sha256;
        let digest: sha2::digest::Output<Sha256> = self.request_digest_bytes()?.into();
        Ok(format!("{digest:x}"))
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
    pub fn records(&self) -> &[BatchV2Record] {
        &self.envelope.records.0
    }
    /// Checks declared batch age and record expiry, without authenticating
    /// origin, collector, workload or policy authority.
    pub fn validate_at(&self, now: time::OffsetDateTime) -> Result<(), BatchError> {
        batch::validate_batch_at(&self.envelope.created_at, self.internal_records(), now)
    }
    /// Minimal legacy source-policy lookup dimensions. Witnesses are excluded.
    pub fn authority_requests(&self) -> impl ExactSizeIterator<Item = crate::AuthorityRequest<'_>> {
        self.internal_records().map(batch::authority_request)
    }
    /// Destination observations paired with their untrusted witness, in record
    /// order. The witness does not establish origin or alter the operation key.
    pub fn operation_observations(
        &self,
    ) -> impl ExactSizeIterator<Item = (crate::OperationObservation<'_>, &OriginWitness)> {
        self.envelope.records.0.iter().map(|wrapper| {
            (
                batch::operation_observation(
                    &wrapper.record,
                    self.tenant_id(),
                    self.collector_id(),
                ),
                &wrapper.origin_witness,
            )
        })
    }
    pub(crate) fn internal_records(&self) -> impl ExactSizeIterator<Item = &Record> {
        self.envelope
            .records
            .0
            .iter()
            .map(|wrapper| &wrapper.record)
    }
}
