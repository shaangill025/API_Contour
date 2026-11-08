//! Signature-checked causal grant data. This alone does not authorize capture.
use crate::{
    Timestamp,
    batch::Bounded,
    policy::{self, Envelope},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use time::{Duration, OffsetDateTime};

const MAX_BYTES: usize = 1_048_576;
const DOMAIN: &[u8] = b"apicontour/causal-grant/1\n";

/// Redacted verification and lease failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalGrantError {
    Size,
    Invalid,
    Key,
    Profile,
    Signature,
    Semantic,
    Lease,
    Disabled,
}
impl fmt::Display for CausalGrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalGrantError {}

/// Separately configured trust roots, never supplied by the signed envelope.
pub struct CausalGrantKeys(Vec<(String, VerifyingKey)>);
impl fmt::Debug for CausalGrantKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalGrantKeys")
    }
}
impl CausalGrantKeys {
    pub fn new(keys: &[(&str, [u8; 32])]) -> Result<Self, CausalGrantError> {
        if keys.is_empty() || keys.len() > 8 {
            return Err(CausalGrantError::Key);
        }
        let mut installed = Vec::new();
        for (id, bytes) in keys {
            if !policy::text_bound(id, 64) || installed.iter().any(|(existing, _)| existing == id) {
                return Err(CausalGrantError::Key);
            }
            let key = VerifyingKey::from_bytes(bytes).map_err(|_| CausalGrantError::Key)?;
            if key.is_weak() {
                return Err(CausalGrantError::Key);
            }
            installed.push(((*id).to_owned(), key));
        }
        Ok(Self(installed))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalGrantEventKind {
    Root,
    Delivery,
    Attempt,
    Loss,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    grant_version: u64,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    tenant_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    collector_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    runtime_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    source_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    lifecycle_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 36>")]
    instance_id: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 64>")]
    causal_profile: String,
    #[serde(deserialize_with = "policy::bounded_string::<_, 64>")]
    profile_sha256: String,
    revision: u64,
    issued_at: Timestamp,
    expires_at: Timestamp,
    enabled: bool,
    event_kinds: Bounded<CausalGrantEventKind, 4>,
    max_batch_events: u64,
    max_batch_bytes: u64,
    queue_bytes: u64,
    queue_ttl_seconds: u64,
}

/// Valid signature and checked grant data, not enrollment or capture authorization.
pub struct VerifiedCausalGrant(Payload, [u8; 32]);
impl fmt::Debug for VerifiedCausalGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedCausalGrant")
    }
}
impl VerifiedCausalGrant {
    pub fn from_signed_json(
        bytes: &[u8],
        keys: &CausalGrantKeys,
        now: OffsetDateTime,
    ) -> Result<Self, CausalGrantError> {
        use CausalGrantError as E;
        if bytes.len() > MAX_BYTES {
            return Err(E::Size);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| E::Invalid)?;
        if envelope.signature_profile != "ed25519-v1" {
            return Err(E::Profile);
        }
        if !policy::text_bound(&envelope.key_id, 64) {
            return Err(E::Key);
        }
        let key = keys
            .0
            .iter()
            .find(|(id, _)| id == &envelope.key_id)
            .ok_or(E::Key)?
            .1;
        if envelope.payload_base64url.is_empty()
            || envelope.payload_base64url.len() > MAX_BYTES
            || envelope.signature_base64url.len() != 86
        {
            return Err(E::Invalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload_base64url)
            .map_err(|_| E::Invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&envelope.signature_base64url)
            .map_err(|_| E::Invalid)?;
        if URL_SAFE_NO_PAD.encode(&payload) != envelope.payload_base64url
            || URL_SAFE_NO_PAD.encode(&signature) != envelope.signature_base64url
        {
            return Err(E::Invalid);
        }
        let signature = Signature::from_slice(&signature).map_err(|_| E::Invalid)?;
        key.verify_strict(&[DOMAIN, &payload].concat(), &signature)
            .map_err(|_| E::Signature)?;
        // Authenticate exact bytes before interpreting the payload.
        let p: Payload = serde_json::from_slice(&payload).map_err(|_| E::Invalid)?;
        let kinds: std::collections::HashSet<_> = p.event_kinds.0.iter().collect();
        if p.grant_version != 1
            || [
                &p.tenant_id,
                &p.collector_id,
                &p.runtime_id,
                &p.source_id,
                &p.lifecycle_id,
                &p.instance_id,
            ]
            .iter()
            .any(|id| !policy::uuid(id))
            || !(p.causal_profile == "nodered_5_0_9_v1"
                || (p.causal_profile == "nodered_5_0_9_wire_v1"
                    && p.profile_sha256
                        == "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e"))
            || p.profile_sha256.len() != 64
            || !p
                .profile_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || p.revision == 0
            || p.event_kinds.0.len() != 4
            || kinds.len() != 4
            || !(1..=500).contains(&p.max_batch_events)
            || !(1..=MAX_BYTES as u64).contains(&p.max_batch_bytes)
            || p.queue_bytes > 268_435_456
            || !(1..=86_400).contains(&p.queue_ttl_seconds)
        {
            return Err(E::Semantic);
        }
        let lease = p.expires_at.instant() - p.issued_at.instant();
        if lease <= Duration::ZERO || lease > Duration::minutes(15) {
            return Err(E::Lease);
        }
        let result = Self(p, Sha256::digest(&payload).into());
        result.validate_at(now)?;
        Ok(result)
    }
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), CausalGrantError> {
        if now < self.issued_at() || now >= self.expires_at() {
            return Err(CausalGrantError::Lease);
        }
        Ok(())
    }
    /// Lease, enabled and queue checks only; enrollment, live session and legacy scope are also required.
    pub fn validate_capture_at(&self, now: OffsetDateTime) -> Result<(), CausalGrantError> {
        self.validate_at(now)?;
        if !self.0.enabled || self.0.queue_bytes == 0 {
            return Err(CausalGrantError::Disabled);
        }
        Ok(())
    }
    pub fn tenant_id(&self) -> &str {
        &self.0.tenant_id
    }
    pub fn collector_id(&self) -> &str {
        &self.0.collector_id
    }
    pub fn runtime_id(&self) -> &str {
        &self.0.runtime_id
    }
    pub fn source_id(&self) -> &str {
        &self.0.source_id
    }
    pub fn lifecycle_id(&self) -> &str {
        &self.0.lifecycle_id
    }
    pub fn instance_id(&self) -> &str {
        &self.0.instance_id
    }
    pub fn causal_profile(&self) -> &str {
        &self.0.causal_profile
    }
    pub fn profile_sha256(&self) -> &str {
        &self.0.profile_sha256
    }
    pub fn revision(&self) -> u64 {
        self.0.revision
    }
    pub fn issued_at(&self) -> OffsetDateTime {
        self.0.issued_at.instant()
    }
    pub fn expires_at(&self) -> OffsetDateTime {
        self.0.expires_at.instant()
    }
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }
    pub fn event_kinds(&self) -> &[CausalGrantEventKind] {
        &self.0.event_kinds.0
    }
    pub fn max_batch_events(&self) -> u64 {
        self.0.max_batch_events
    }
    pub fn max_batch_bytes(&self) -> u64 {
        self.0.max_batch_bytes
    }
    pub fn queue_bytes(&self) -> u64 {
        self.0.queue_bytes
    }
    pub fn queue_ttl_seconds(&self) -> u64 {
        self.0.queue_ttl_seconds
    }
    /// Digest of exact authenticated payload bytes, for future revision consistency checks.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.1
    }
}
