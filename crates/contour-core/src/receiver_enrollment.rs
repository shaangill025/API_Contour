//! Strict receiver enrollment data decoding. This is not authority or peer proof.
use crate::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_RECEIVER_ENROLLMENT_BYTES: usize = 4096;
const DOMAIN: &[u8] = b"apicontour/receiver-enrollment/1\n";
const PROFILE: &str = "00000000-0000-4000-8000-000000000504";
const MANIFEST: &str = "af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d";
const ARTIFACT: &str = "707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    artifact_sha256: String,
    backend_leaf_sha256: String,
    enrollment_generation: String,
    evidence_credential_id: String,
    evidence_leaf_sha256: String,
    expires_at: String,
    export_leaf_sha256: String,
    grant_digest: String,
    instance_id: String,
    issued_at: String,
    lifecycle_id: String,
    policy_envelope_sha256: String,
    policy_revision: String,
    product_credential_id: String,
    product_leaf_sha256: String,
    profile_id: String,
    profile_manifest_sha256: String,
    runtime_id: String,
    session_epoch: String,
    session_nonce: String,
    tenant_id: String,
    version: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverEnrollmentError;
impl fmt::Display for ReceiverEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid receiver enrollment data")
    }
}
impl std::error::Error for ReceiverEnrollmentError {}

/// Validated immutable data. Its commitment does not establish who issued it.
pub struct ReceiverEnrollment {
    wire: Wire,
    epoch: u64,
    revision: u64,
    issued: Timestamp,
    expires: Timestamp,
    commitment: [u8; 32],
}
impl fmt::Debug for ReceiverEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiverEnrollment")
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}
fn positive(value: &str) -> Result<u64, ReceiverEnrollmentError> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ReceiverEnrollmentError);
    }
    value.parse::<u64>().map_err(|_| ReceiverEnrollmentError)
}
fn timestamp(value: &str) -> Result<Timestamp, ReceiverEnrollmentError> {
    let bytes = value.as_bytes();
    if bytes.len() != 27
        || bytes[19] != b'.'
        || bytes[26] != b'Z'
        || !bytes[20..26].iter().all(u8::is_ascii_digit)
    {
        return Err(ReceiverEnrollmentError);
    }
    Timestamp::parse(value).map_err(|_| ReceiverEnrollmentError)
}
fn digest(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update((body.len() as u32).to_be_bytes());
    h.update(body);
    h.finalize().into()
}

impl ReceiverEnrollment {
    /// Verify exact canonical bytes and their independently supplied commitment.
    pub fn decode(body: &[u8], expected: &[u8; 32]) -> Result<Self, ReceiverEnrollmentError> {
        if body.is_empty() || body.len() > MAX_RECEIVER_ENROLLMENT_BYTES {
            return Err(ReceiverEnrollmentError);
        }
        let wire: Wire = serde_json::from_slice(body).map_err(|_| ReceiverEnrollmentError)?;
        if serde_json::to_vec(&wire).map_err(|_| ReceiverEnrollmentError)? != body {
            return Err(ReceiverEnrollmentError);
        }
        if wire.version != 1
            || wire.profile_id != PROFILE
            || wire.profile_manifest_sha256 != MANIFEST
            || wire.artifact_sha256 != ARTIFACT
            || !lower_hex(&wire.enrollment_generation, 32)
            || wire.enrollment_generation.bytes().all(|b| b == b'0')
            || [
                &wire.backend_leaf_sha256,
                &wire.evidence_leaf_sha256,
                &wire.export_leaf_sha256,
                &wire.grant_digest,
                &wire.policy_envelope_sha256,
                &wire.product_leaf_sha256,
            ]
            .into_iter()
            .any(|v| !lower_hex(v, 64))
            || [
                &wire.evidence_credential_id,
                &wire.instance_id,
                &wire.lifecycle_id,
                &wire.product_credential_id,
                &wire.profile_id,
                &wire.runtime_id,
                &wire.session_nonce,
                &wire.tenant_id,
            ]
            .into_iter()
            .any(|v| !uuid(v))
        {
            return Err(ReceiverEnrollmentError);
        }
        let epoch = positive(&wire.session_epoch)?;
        let revision = positive(&wire.policy_revision)?;
        let issued = timestamp(&wire.issued_at)?;
        let expires = timestamp(&wire.expires_at)?;
        if issued.instant() >= expires.instant() {
            return Err(ReceiverEnrollmentError);
        }
        let commitment = digest(body);
        if &commitment != expected {
            return Err(ReceiverEnrollmentError);
        }
        Ok(Self {
            wire,
            epoch,
            revision,
            issued,
            expires,
            commitment,
        })
    }
    pub fn session_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn policy_revision(&self) -> u64 {
        self.revision
    }
    pub fn issued_at(&self) -> &Timestamp {
        &self.issued
    }
    pub fn expires_at(&self) -> &Timestamp {
        &self.expires
    }
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

macro_rules! string_fields {
    ($($name:ident),+ $(,)?) => { impl ReceiverEnrollment { $(pub fn $name(&self) -> &str { &self.wire.$name })+ } };
}
string_fields!(
    artifact_sha256,
    backend_leaf_sha256,
    enrollment_generation,
    evidence_credential_id,
    evidence_leaf_sha256,
    export_leaf_sha256,
    grant_digest,
    instance_id,
    lifecycle_id,
    policy_envelope_sha256,
    product_credential_id,
    product_leaf_sha256,
    profile_id,
    profile_manifest_sha256,
    runtime_id,
    session_nonce,
    tenant_id
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn vector() -> (Vec<u8>, [u8; 32]) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../docs/specification/fixtures/receiver-enrollment-v1.json"
        ))
        .unwrap();
        let body = fixture["canonical_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        let expected = fixture["commitment_sha256"].as_str().unwrap();
        let mut bytes = [0; 32];
        for (i, chunk) in expected.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        (body, bytes)
    }
    fn changed(key: &str, value: Value) -> Vec<u8> {
        let (body, _) = vector();
        let mut item: Value = serde_json::from_slice(&body).unwrap();
        item[key] = value;
        serde_json::to_vec(&item).unwrap()
    }
    fn reject(body: &[u8]) {
        // Recompute the commitment so rejection is attributable to the encoding.
        assert!(ReceiverEnrollment::decode(body, &digest(body)).is_err());
    }
    #[test]
    fn shared_vector_and_commitment() {
        let (body, expected) = vector();
        assert_eq!(body.len(), 1351);
        assert_eq!(digest(&body), expected);
        assert_eq!(
            expected,
            [
                0x61, 0xcc, 0x5e, 0x6a, 0x14, 0x96, 0x93, 0xdb, 0xdf, 0xe4, 0x64, 0x22, 0x11, 0xd0,
                0x7a, 0x3c, 0xd6, 0xe9, 0x26, 0xe1, 0x79, 0x54, 0xfe, 0x95, 0xd8, 0xd9, 0x44, 0xa8,
                0xd8, 0xa2, 0xe2, 0x30
            ]
        );
        let result = ReceiverEnrollment::decode(&body, &expected).unwrap();
        assert_eq!(result.session_epoch(), 1);
        assert_eq!(result.policy_revision(), 1);
        assert_eq!(result.profile_manifest_sha256(), MANIFEST);
        assert_eq!(result.artifact_sha256(), ARTIFACT);
        assert_eq!(format!("{result:?}"), "ReceiverEnrollment");
        assert!(ReceiverEnrollment::decode(&body, &[0; 32]).is_err());
        let mut other_domain = Sha256::new();
        other_domain.update(b"apicontour/receiver-enrollment/2\n");
        other_domain.update((body.len() as u32).to_be_bytes());
        other_domain.update(&body);
        assert!(ReceiverEnrollment::decode(&body, &other_domain.finalize().into()).is_err());
        let mut wrong_length = Sha256::new();
        wrong_length.update(DOMAIN);
        wrong_length.update(((body.len() + 1) as u32).to_be_bytes());
        wrong_length.update(&body);
        assert!(ReceiverEnrollment::decode(&body, &wrong_length.finalize().into()).is_err());
    }
    #[test]
    fn rejects_noncanonical_and_structural_forms() {
        let (body, _) = vector();
        let text = std::str::from_utf8(&body).unwrap();
        reject(format!(" {text}").as_bytes());
        reject(
            text.replace("\"artifact_sha256\":", "\"unknown\":0,\"artifact_sha256\":")
                .as_bytes(),
        );
        reject(
            text.replace(
                "\"artifact_sha256\":",
                "\"artifact_sha256\":\"duplicate\",\"artifact_sha256\":",
            )
            .as_bytes(),
        );
        reject(
            text.replace("\"artifact_sha256\"", "\"artifact\\u005fsha256\"")
                .as_bytes(),
        );
        let mut item: Value = serde_json::from_slice(&body).unwrap();
        item.as_object_mut().unwrap().remove("session_nonce");
        reject(&serde_json::to_vec(&item).unwrap());
        reject(&vec![b' '; MAX_RECEIVER_ENROLLMENT_BYTES + 1]);
        let first_end = text.find(",\"backend_leaf_sha256\":").unwrap();
        let second_end = text.find(",\"enrollment_generation\":").unwrap();
        let reordered = format!(
            "{{{},{}",
            &text[first_end + 1..second_end],
            &text[1..first_end]
        );
        let reordered = format!("{}{}", reordered, &text[second_end..]);
        reject(reordered.as_bytes());
    }
    #[test]
    fn rejects_invalid_typed_values_and_accepts_u64_max() {
        for (key, value) in [
            ("session_epoch", json!(1)),
            ("session_epoch", json!("0")),
            ("session_epoch", json!("01")),
            ("session_epoch", json!("18446744073709551616")),
            ("policy_revision", json!("-1")),
            ("version", json!(true)),
            ("version", json!(1.0)),
            ("tenant_id", json!("00000000-0000-4000-8000-00000000000A")),
            (
                "enrollment_generation",
                json!("00000000000000000000000000000000"),
            ),
            ("backend_leaf_sha256", json!("A".repeat(64))),
            ("profile_manifest_sha256", json!(ARTIFACT)),
            ("artifact_sha256", json!(MANIFEST)),
            ("issued_at", json!("0000-01-01T00:00:00.000000Z")),
            ("issued_at", json!("2026-02-29T00:00:00.000000Z")),
            ("issued_at", json!("2026-11-12T23:54:00.12345Z")),
            ("issued_at", json!("2026-11-12T23:54:00.123456+00:00")),
            ("expires_at", json!("2026-11-12T23:54:00.123456Z")),
        ] {
            reject(&changed(key, value));
        }
        let body = changed("session_epoch", json!("18446744073709551615"));
        assert_eq!(
            ReceiverEnrollment::decode(&body, &digest(&body))
                .unwrap()
                .session_epoch(),
            u64::MAX
        );
    }
}
