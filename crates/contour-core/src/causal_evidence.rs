//! Untrusted causal-evidence data. Parsing and digests do not confer authority.
use crate::{BatchError, batch};
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_CAUSAL_BINDING_BYTES: usize = 2048;
pub const MAX_CAUSAL_EVIDENCE_BYTES: usize = 4096;

fn required_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn epoch(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('0')
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u64>().is_ok_and(|v| v > 0)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    wire_version: u64,
    tenant_id: String,
    gateway_id: String,
    gateway_generation: String,
    collector_id: String,
    record_id: String,
    producer_runtime_id: String,
    producer_session_epoch: String,
    producer_attempt_id: String,
    marker_digest: String,
    receiver_runtime_id: String,
    receiver_session_epoch: String,
    delivery_handle: String,
    #[serde(deserialize_with = "required_nullable")]
    retry_of: Option<String>,
}
impl BindingWire {
    fn valid(&self) -> bool {
        self.wire_version == 1
            && [
                &self.tenant_id,
                &self.gateway_id,
                &self.collector_id,
                &self.record_id,
                &self.producer_runtime_id,
                &self.receiver_runtime_id,
            ]
            .iter()
            .all(|s| batch::uuid(s))
            && [
                &self.gateway_generation,
                &self.producer_attempt_id,
                &self.delivery_handle,
            ]
            .iter()
            .all(|s| hex(s, 32))
            && hex(&self.marker_digest, 64)
            && epoch(&self.producer_session_epoch)
            && epoch(&self.receiver_session_epoch)
            && self.retry_of.as_ref().is_none_or(|s| hex(s, 32))
    }
}

/// Syntactically checked binding; its contents are untrusted claims.
///
/// ```compile_fail
/// use contour_core::CausalEvidenceBinding;
/// let _: CausalEvidenceBinding = serde_json::from_slice(b"{}").unwrap();
/// ```
#[derive(Serialize)]
#[serde(transparent)]
pub struct CausalEvidenceBinding(BindingWire);
impl CausalEvidenceBinding {
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_CAUSAL_BINDING_BYTES {
            return Err(BatchError::Size);
        }
        let value: BindingWire = serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        if !value.valid() {
            return Err(BatchError::Semantic);
        }
        Ok(Self(value))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchError> {
        batch::canonical_encode(&self.0)
    }
    pub fn digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.0, b"apicontour/causal-evidence/binding/1\n")
    }
    pub fn tenant_id(&self) -> &str {
        &self.0.tenant_id
    }
    pub fn delivery_handle(&self) -> &str {
        &self.0.delivery_handle
    }
}

fn bounded_binding<'de, D: Deserializer<'de>>(d: D) -> Result<CausalEvidenceBinding, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
    CausalEvidenceBinding::from_wire_json(raw.get().as_bytes()).map_err(serde::de::Error::custom)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverWire {
    wire_version: u64,
    #[serde(deserialize_with = "bounded_binding")]
    binding: CausalEvidenceBinding,
    batch_id: String,
    signed_marker: String,
}
/// Syntactically checked observer claim, not an authenticated assertion.
/// ```compile_fail
/// use contour_core::CausalEvidenceObserver;
/// let _: CausalEvidenceObserver = serde_json::from_slice(b"{}").unwrap();
/// ```
pub struct CausalEvidenceObserver(ObserverWire);
impl CausalEvidenceObserver {
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_CAUSAL_EVIDENCE_BYTES {
            return Err(BatchError::Size);
        }
        let value: ObserverWire = serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        if value.wire_version != 1
            || !value.binding.0.valid()
            || !batch::uuid(&value.batch_id)
            || value.signed_marker.len() > 1024
            || !value.signed_marker.starts_with("ac1.")
            || !value
                .signed_marker
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
            || batch::canonical_encode(&value.binding)?.len() > MAX_CAUSAL_BINDING_BYTES
        {
            return Err(BatchError::Semantic);
        }
        Ok(Self(value))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchError> {
        batch::canonical_encode(&self.0)
    }
    pub fn digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.0, b"apicontour/causal-evidence/observer/1\n")
    }
    pub fn binding(&self) -> &CausalEvidenceBinding {
        &self.0.binding
    }
    pub fn batch_id(&self) -> &str {
        &self.0.batch_id
    }
    pub fn signed_marker(&self) -> &str {
        &self.0.signed_marker
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverWire {
    wire_version: u64,
    tenant_id: String,
    gateway_id: String,
    gateway_generation: String,
    delivery_handle: String,
    receiver_runtime_id: String,
    receiver_session_epoch: String,
    local_root: String,
    binding_digest: String,
}
/// Syntactically checked receiver claim, not a durable receipt.
/// ```compile_fail
/// use contour_core::CausalEvidenceReceiver;
/// let _: CausalEvidenceReceiver = serde_json::from_slice(b"{}").unwrap();
/// ```
pub struct CausalEvidenceReceiver(ReceiverWire);
impl CausalEvidenceReceiver {
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_CAUSAL_EVIDENCE_BYTES {
            return Err(BatchError::Size);
        }
        let value: ReceiverWire = serde_json::from_slice(bytes).map_err(|_| BatchError::Invalid)?;
        if value.wire_version != 1
            || ![
                &value.tenant_id,
                &value.gateway_id,
                &value.receiver_runtime_id,
            ]
            .iter()
            .all(|s| batch::uuid(s))
            || ![
                &value.gateway_generation,
                &value.delivery_handle,
                &value.local_root,
            ]
            .iter()
            .all(|s| hex(s, 32))
            || !hex(&value.binding_digest, 64)
            || !epoch(&value.receiver_session_epoch)
        {
            return Err(BatchError::Semantic);
        }
        Ok(Self(value))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchError> {
        batch::canonical_encode(&self.0)
    }
    pub fn digest_bytes(&self) -> Result<[u8; 32], BatchError> {
        batch::canonical_digest(&self.0, b"apicontour/causal-evidence/receiver/1\n")
    }
    pub fn tenant_id(&self) -> &str {
        &self.0.tenant_id
    }
    pub fn delivery_handle(&self) -> &str {
        &self.0.delivery_handle
    }
}
