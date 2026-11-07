//! Signature-authenticated marker data, not admission, an original-peer witness,
//! producer attestation, replay prevention, or proof of a causal edge.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_CAUSAL_MARKER_BYTES: usize = 1024;
const SIGN_DOMAIN: &[u8] = b"apicontour/causal-marker/1\n";
const WIRE_DOMAIN: &[u8] = b"apicontour/causal-marker-wire/1\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalMarkerError {
    Invalid,
    Scope,
    Key,
    Signature,
    Size,
}
impl fmt::Display for CausalMarkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CausalMarkerError {}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Expected identity is trusted configuration, never derived from a marker.
#[derive(Clone, PartialEq, Eq)]
pub struct CausalMarkerScope {
    tenant_id: String,
    runtime_id: String,
    session_epoch: u64,
    product_leaf_sha256: String,
}
impl CausalMarkerScope {
    pub fn new(
        tenant: &str,
        runtime: &str,
        epoch: u64,
        leaf: &str,
    ) -> Result<Self, CausalMarkerError> {
        if !crate::policy::uuid(tenant)
            || !crate::policy::uuid(runtime)
            || epoch == 0
            || !hex(leaf, 64)
        {
            return Err(CausalMarkerError::Scope);
        }
        Ok(Self {
            tenant_id: tenant.to_owned(),
            runtime_id: runtime.to_owned(),
            session_epoch: epoch,
            product_leaf_sha256: leaf.to_owned(),
        })
    }
}
impl fmt::Debug for CausalMarkerScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalMarkerScope")
    }
}
// Declaration order is the canonical ASCII key order, verified again on decode.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    activity: String,
    attempt: String,
    product_leaf_sha256: String,
    root: String,
    runtime_id: String,
    session_epoch: u64,
    tenant_id: String,
    wire_version: u64,
}
impl Payload {
    fn valid(&self) -> bool {
        self.wire_version == 1
            && crate::policy::uuid(&self.tenant_id)
            && crate::policy::uuid(&self.runtime_id)
            && self.session_epoch > 0
            && hex(&self.product_leaf_sha256, 64)
            && hex(&self.root, 32)
            && hex(&self.activity, 32)
            && hex(&self.attempt, 32)
    }
    fn in_scope(&self, s: &CausalMarkerScope) -> bool {
        self.tenant_id == s.tenant_id
            && self.runtime_id == s.runtime_id
            && self.session_epoch == s.session_epoch
            && self.product_leaf_sha256 == s.product_leaf_sha256
    }
    fn bytes(&self) -> Result<Vec<u8>, CausalMarkerError> {
        serde_json::to_vec(self).map_err(|_| CausalMarkerError::Invalid)
    }
}
/// Validated signing input. The caller is responsible for holding a private key
/// in a trusted runtime initializer and for live authorization.
pub struct CausalMarkerClaim(Payload);
impl CausalMarkerClaim {
    pub fn new(
        scope: &CausalMarkerScope,
        root: &str,
        activity: &str,
        attempt: &str,
    ) -> Result<Self, CausalMarkerError> {
        if !hex(root, 32) || !hex(activity, 32) || !hex(attempt, 32) {
            return Err(CausalMarkerError::Invalid);
        }
        let p = Payload {
            activity: activity.to_owned(),
            attempt: attempt.to_owned(),
            product_leaf_sha256: scope.product_leaf_sha256.clone(),
            root: root.to_owned(),
            runtime_id: scope.runtime_id.clone(),
            session_epoch: scope.session_epoch,
            tenant_id: scope.tenant_id.clone(),
            wire_version: 1,
        };
        if !p.valid() {
            return Err(CausalMarkerError::Invalid);
        }
        Ok(Self(p))
    }
    /// The seed is trusted private signing material; never put it in a marker.
    pub fn sign(&self, seed: &[u8; 32]) -> Result<SignedCausalMarker, CausalMarkerError> {
        let payload = self.0.bytes()?;
        let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + payload.len());
        message.extend_from_slice(SIGN_DOMAIN);
        message.extend_from_slice(&payload);
        let key = SigningKey::from_bytes(seed);
        if key.verifying_key().is_weak() {
            return Err(CausalMarkerError::Key);
        }
        let signature = key.sign(&message);
        let header = format!(
            "ac1.{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        if header.len() > MAX_CAUSAL_MARKER_BYTES {
            return Err(CausalMarkerError::Size);
        }
        let digest = wire_digest(header.as_bytes());
        Ok(SignedCausalMarker { header, digest })
    }
}
impl fmt::Debug for CausalMarkerClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalMarkerClaim")
    }
}
fn wire_digest(header: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(WIRE_DOMAIN);
    h.update(header);
    h.finalize().into()
}
/// Immutable signed header and its digest. Neither is proof of live authority.
pub struct SignedCausalMarker {
    header: String,
    digest: [u8; 32],
}
impl SignedCausalMarker {
    pub fn header(&self) -> &str {
        &self.header
    }
    pub fn marker_digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl fmt::Debug for SignedCausalMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedCausalMarker")
    }
}
/// Verifies against a caller-supplied trusted key and expected scope.
pub struct CausalMarkerVerifier {
    key: VerifyingKey,
    scope: CausalMarkerScope,
}
impl CausalMarkerVerifier {
    pub fn new(key: [u8; 32], scope: CausalMarkerScope) -> Result<Self, CausalMarkerError> {
        let original = key;
        let key = VerifyingKey::from_bytes(&original).map_err(|_| CausalMarkerError::Key)?;
        let point = key.to_edwards();
        if key.is_weak() || point.compress().to_bytes() != original || !point.is_torsion_free() {
            return Err(CausalMarkerError::Key);
        }
        Ok(Self { key, scope })
    }
    pub fn verify(&self, header: &str) -> Result<VerifiedCausalMarker, CausalMarkerError> {
        if header.len() > MAX_CAUSAL_MARKER_BYTES {
            return Err(CausalMarkerError::Size);
        }
        if !header.is_ascii() {
            return Err(CausalMarkerError::Invalid);
        }
        let mut parts = header.split('.');
        if parts.next() != Some("ac1") {
            return Err(CausalMarkerError::Invalid);
        }
        let encoded = parts.next().ok_or(CausalMarkerError::Invalid)?;
        let signed = parts.next().ok_or(CausalMarkerError::Invalid)?;
        if parts.next().is_some() || encoded.is_empty() || signed.len() != 86 {
            return Err(CausalMarkerError::Invalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CausalMarkerError::Invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signed)
            .map_err(|_| CausalMarkerError::Invalid)?;
        if URL_SAFE_NO_PAD.encode(&payload) != encoded
            || URL_SAFE_NO_PAD.encode(&signature) != signed
        {
            return Err(CausalMarkerError::Invalid);
        }
        let signature =
            Signature::from_slice(&signature).map_err(|_| CausalMarkerError::Invalid)?;
        let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + payload.len());
        message.extend_from_slice(SIGN_DOMAIN);
        message.extend_from_slice(&payload);
        self.key
            .verify_strict(&message, &signature)
            .map_err(|_| CausalMarkerError::Signature)?;
        // Signature authentication precedes interpretation. Re-encoding enforces
        // exact key ordering, spelling, numbers and rejection of aliases.
        let p: Payload =
            serde_json::from_slice(&payload).map_err(|_| CausalMarkerError::Invalid)?;
        if !p.valid() || p.bytes()? != payload {
            return Err(CausalMarkerError::Invalid);
        }
        if !p.in_scope(&self.scope) {
            return Err(CausalMarkerError::Scope);
        }
        Ok(VerifiedCausalMarker {
            payload: p,
            digest: wire_digest(header.as_bytes()),
        })
    }
}
impl fmt::Debug for CausalMarkerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalMarkerVerifier")
    }
}
/// Signature-authenticated data only; not replay prevention, transport witness,
/// live authorization, producer qualification, or causal edge proof.
pub struct VerifiedCausalMarker {
    payload: Payload,
    digest: [u8; 32],
}
impl VerifiedCausalMarker {
    pub fn root(&self) -> &str {
        &self.payload.root
    }
    pub fn activity(&self) -> &str {
        &self.payload.activity
    }
    pub fn attempt(&self) -> &str {
        &self.payload.attempt
    }
    pub fn marker_digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl fmt::Debug for VerifiedCausalMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedCausalMarker")
    }
}
