use crate::{Timestamp, UnsignedInteger};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, marker::PhantomData};
use time::{Duration, OffsetDateTime};

const MAX_ENVELOPE_BYTES: usize = 1_048_576;
const PROFILE: &str = "ed25519-v1";
const DOMAIN: &[u8] = b"apicontour/policy/1\n";

/// Safe rejection categories, without signed data or key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Size,
    Invalid,
    Key,
    Profile,
    Signature,
    Semantic,
    Identity,
    Lease,
    Disabled,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}

/// Trusted release configuration, never constructed from envelope fields.
pub struct PolicyKeys(Vec<(String, VerifyingKey)>);
impl fmt::Debug for PolicyKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyKeys")
    }
}
impl PolicyKeys {
    pub fn new(keys: &[(&str, [u8; 32])]) -> Result<Self, PolicyError> {
        if keys.is_empty() || keys.len() > 8 {
            return Err(PolicyError::Key);
        }
        let mut installed = Vec::new();
        for (id, bytes) in keys {
            if !text_bound(id, 64) || installed.iter().any(|(existing, _)| existing == id) {
                return Err(PolicyError::Key);
            }
            let key = VerifyingKey::from_bytes(bytes).map_err(|_| PolicyError::Key)?;
            if key.is_weak() {
                return Err(PolicyError::Key);
            }
            installed.push(((*id).to_owned(), key));
        }
        Ok(Self(installed))
    }
}

/// Signature-authenticated, schema-checked and identity-bound policy.
/// Verification is not enrollment, revocation checking or anti-rollback storage.
pub struct VerifiedPolicy(Policy, [u8; 32]);
impl fmt::Debug for VerifiedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedPolicy")
    }
}
impl VerifiedPolicy {
    pub fn from_signed_json(
        bytes: &[u8],
        keys: &PolicyKeys,
        tenant: &str,
        collector: &str,
        now: OffsetDateTime,
    ) -> Result<Self, PolicyError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(PolicyError::Size);
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| PolicyError::Invalid)?;
        if envelope.signature_profile != PROFILE {
            return Err(PolicyError::Profile);
        }
        if !text_bound(&envelope.key_id, 64) {
            return Err(PolicyError::Key);
        }
        let key = keys
            .0
            .iter()
            .find(|(id, _)| id == &envelope.key_id)
            .ok_or(PolicyError::Key)?
            .1;
        if envelope.payload_base64url.is_empty()
            || envelope.payload_base64url.len() > 1_048_576
            || envelope.signature_base64url.len() != 86
        {
            return Err(PolicyError::Invalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&envelope.payload_base64url)
            .map_err(|_| PolicyError::Invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&envelope.signature_base64url)
            .map_err(|_| PolicyError::Invalid)?;
        if URL_SAFE_NO_PAD.encode(&payload) != envelope.payload_base64url
            || URL_SAFE_NO_PAD.encode(&signature) != envelope.signature_base64url
        {
            return Err(PolicyError::Invalid);
        }
        let signature = Signature::from_slice(&signature).map_err(|_| PolicyError::Invalid)?;
        key.verify_strict(&[DOMAIN, &payload].concat(), &signature)
            .map_err(|_| PolicyError::Signature)?;
        // Authentication precedes parsing; never normalize signing bytes.
        let policy: Policy = serde_json::from_slice(&payload).map_err(|_| PolicyError::Invalid)?;
        policy.validate()?;
        if !uuid(tenant)
            || !uuid(collector)
            || policy.tenant_id != tenant
            || policy.collector_id != collector
        {
            return Err(PolicyError::Identity);
        }
        let result = Self(policy, Sha256::digest(&payload).into());
        result.validate_at(now)?;
        Ok(result)
    }
    pub fn tenant_id(&self) -> &str {
        &self.0.tenant_id
    }
    pub fn collector_id(&self) -> &str {
        &self.0.collector_id
    }
    pub fn revision(&self) -> u64 {
        self.0.revision.get()
    }
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }
    pub fn issued_at(&self) -> OffsetDateTime {
        self.0.issued_at.instant()
    }
    pub fn expires_at(&self) -> OffsetDateTime {
        self.0.expires_at.instant()
    }
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), PolicyError> {
        if now < self.issued_at() || now >= self.expires_at() {
            return Err(PolicyError::Lease);
        }
        Ok(())
    }
    /// Lease/enabled checks only. Callers must also check enrollment, revocation
    /// and persisted highest revision before enabling capture.
    pub fn validate_capture_at(&self, now: OffsetDateTime) -> Result<(), PolicyError> {
        self.validate_at(now)?;
        if !self.enabled() {
            return Err(PolicyError::Disabled);
        }
        Ok(())
    }
    pub(crate) fn same_content(&self, other: &Self) -> bool {
        self.1 == other.1
    }
    pub(crate) fn content_digest(&self) -> [u8; 32] {
        self.1
    }
    pub(crate) fn queue_bytes(&self) -> u64 {
        self.0.queue_bytes.get()
    }
    pub(crate) fn approves(&self, service: &str, technique: &str, parser: &str) -> bool {
        self.0.service_ids.0.iter().any(|id| id == service)
            && self.0.techniques.0.iter().any(|name| name == technique)
            && self.0.parser_profiles.0.iter().any(|name| name == parser)
    }
    pub(crate) fn approves_name(&self, name: &str) -> bool {
        self.0.approved_names.0.iter().any(|item| item == name)
    }
    pub(crate) fn approves_segment(&self, name: &str) -> bool {
        self.0
            .approved_route_segments
            .0
            .iter()
            .any(|item| item == name)
    }
    pub(crate) fn denied_templates(&self) -> &[String] {
        &self.0.denied_templates.0
    }
    pub(crate) fn depth_limit(&self) -> usize {
        self.0.depth_limit.get() as usize
    }
    pub(crate) fn ttl(&self) -> u64 {
        self.0.queue_ttl_seconds.get()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(deserialize_with = "bounded_string::<_, 1048576>")]
    payload_base64url: String,
    #[serde(deserialize_with = "bounded_string::<_, 4096>")]
    signature_base64url: String,
    #[serde(deserialize_with = "bounded_string::<_, 64>")]
    key_id: String,
    #[serde(deserialize_with = "bounded_string::<_, 64>")]
    signature_profile: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    #[serde(deserialize_with = "bounded_string::<_, 36>")]
    tenant_id: String,
    #[serde(deserialize_with = "bounded_string::<_, 36>")]
    collector_id: String,
    revision: UnsignedInteger,
    issued_at: Timestamp,
    expires_at: Timestamp,
    enabled: bool,
    service_ids: Bounded<200, 36>,
    techniques: Bounded<16, 9>,
    approved_names: Bounded<4096, 64>,
    denied_templates: Bounded<1024, 256>,
    inspection_bytes: UnsignedInteger,
    depth_limit: UnsignedInteger,
    queue_bytes: UnsignedInteger,
    queue_ttl_seconds: UnsignedInteger,
    durable_queue_enabled: bool,
    approved_route_segments: Bounded<4096, 64>,
    parser_profiles: Bounded<128, 64>,
}
impl Policy {
    fn validate(&self) -> Result<(), PolicyError> {
        // Parsed strictly; queue behavior belongs to a later consumer.
        let _ = self.durable_queue_enabled;
        if !uuid(&self.tenant_id)
            || !uuid(&self.collector_id)
            || self.revision.get() == 0
            || self.service_ids.0.iter().any(|id| !uuid(id))
            || self.techniques.0.iter().any(|name| {
                ![
                    "gateway",
                    "ebpf",
                    "browser",
                    "android",
                    "ios",
                    "cloud",
                    "messaging",
                    "runtime",
                ]
                .contains(&name.as_str())
            })
            || self
                .approved_names
                .0
                .iter()
                .any(|name| !text_bound(name, 64))
            || self
                .denied_templates
                .0
                .iter()
                .any(|name| !text_bound(name, 256))
            || self
                .approved_route_segments
                .0
                .iter()
                .any(|name| !text_bound(name, 64))
            || self.parser_profiles.0.iter().any(|name| !profile(name))
            || !unique(&self.approved_route_segments.0)
            || !unique(&self.parser_profiles.0)
            || self.inspection_bytes.get() > 65_536
            || !(1..=32).contains(&self.depth_limit.get())
            || self.queue_bytes.get() > 268_435_456
            || self.queue_ttl_seconds.get() > 86_400
        {
            return Err(PolicyError::Semantic);
        }
        let lease = self.expires_at.instant() - self.issued_at.instant();
        if lease <= Duration::ZERO || lease > Duration::minutes(15) {
            return Err(PolicyError::Lease);
        }
        Ok(())
    }
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
fn text_bound(text: &str, max: usize) -> bool {
    !text.is_empty() && text.chars().take(max + 1).count() <= max
}
pub(crate) fn profile(text: &str) -> bool {
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
fn bounded_string<'de, D: Deserializer<'de>, const N: usize>(
    decoder: D,
) -> Result<String, D::Error> {
    struct Text<const N: usize>;
    impl<const N: usize> Visitor<'_> for Text<N> {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded policy string")
        }
        fn visit_str<E: de::Error>(self, text: &str) -> Result<String, E> {
            if !text_bound(text, N) {
                return Err(E::custom("string limit"));
            }
            Ok(text.to_owned())
        }
    }
    decoder.deserialize_str(Text::<N>)
}
struct Text<const N: usize>(String);
impl<'de, const N: usize> Deserialize<'de> for Text<N> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        bounded_string::<D, N>(decoder).map(Self)
    }
}
struct Bounded<const N: usize, const L: usize>(Vec<String>);
impl<'de, const N: usize, const L: usize> Deserialize<'de> for Bounded<N, L> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct List<const N: usize, const L: usize>(PhantomData<()>);
        impl<'de, const N: usize, const L: usize> Visitor<'de> for List<N, L> {
            type Value = Bounded<N, L>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded policy list")
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
                    match sequence.next_element::<Text<L>>()? {
                        Some(value) => values.push(value.0),
                        None => break,
                    }
                }
                Ok(Bounded(values))
            }
        }
        decoder.deserialize_seq(List::<N, L>(PhantomData))
    }
}
