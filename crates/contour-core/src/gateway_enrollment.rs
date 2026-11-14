//! Strict SQL26 gateway metadata data codec; this conveys no authority.
use crate::Timestamp;
use sha2::{Digest, Sha256};
use std::fmt;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayEnrollmentError;
impl fmt::Display for GatewayEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid gateway enrollment data")
    }
}
impl std::error::Error for GatewayEnrollmentError {}

/// Immutable data and SHA-256 of the canonical bytes; the hash is not an authority claim.
pub struct GatewayEnrollment {
    canonical: Vec<u8>,
    value: serde_json::Value,
    hash: [u8; 32],
    issued: OffsetDateTime,
    expires: OffsetDateTime,
}
impl fmt::Debug for GatewayEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayEnrollment")
    }
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
impl GatewayEnrollment {
    pub fn decode(body: &[u8]) -> Result<Self, GatewayEnrollmentError> {
        let bad = || GatewayEnrollmentError;
        if body.is_empty() || body.len() > 4096 {
            return Err(bad());
        }
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| bad())?;
        if serde_json::to_vec(&value).map_err(|_| bad())? != body {
            return Err(bad());
        }
        let obj = value.as_object().ok_or_else(bad)?;
        let keys = [
            "tenant_id",
            "gateway_id",
            "collector_id",
            "source_id",
            "project_id",
            "service_id",
            "environment_id",
            "deployment_id",
            "instance_id",
            "provision_nonce",
            "observer_leaf",
            "backend_client_leaf",
            "policy_revision",
            "policy_issued",
            "policy_expires",
            "ttl_microseconds",
            "generation",
            "issued_at",
            "expires_at",
        ];
        if obj.len() != keys.len()
            || keys
                .iter()
                .any(|k| !obj.get(*k).is_some_and(|v| v.is_string()))
        {
            return Err(bad());
        }
        let text = |k: &str| obj.get(k).and_then(|v| v.as_str()).ok_or_else(bad);
        for key in [
            "tenant_id",
            "gateway_id",
            "collector_id",
            "source_id",
            "project_id",
            "service_id",
            "environment_id",
            "deployment_id",
            "instance_id",
        ] {
            if !uuid(text(key)?) {
                return Err(bad());
            }
        }
        for key in ["provision_nonce", "observer_leaf", "backend_client_leaf"] {
            if !hex(text(key)?, 64) {
                return Err(bad());
            }
        }
        if !hex(text("generation")?, 32)
            || text("generation")?.bytes().all(|b| b == b'0')
            || text("observer_leaf")? == text("backend_client_leaf")?
        {
            return Err(bad());
        }
        let positive = |key: &str| -> Result<u64, GatewayEnrollmentError> {
            let v = text(key)?;
            if v.is_empty() || v.starts_with('0') || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            v.parse().map_err(|_| bad())
        };
        let _revision = positive("policy_revision")?;
        let ttl = positive("ttl_microseconds")?;
        if ttl > 86_400_000_000 {
            return Err(bad());
        }
        let timestamp = |key: &str| -> Result<OffsetDateTime, GatewayEnrollmentError> {
            let v = text(key)?;
            let b = v.as_bytes();
            if b.len() != 27
                || b[19] != b'.'
                || b[26] != b'Z'
                || !b[20..26].iter().all(u8::is_ascii_digit)
            {
                return Err(bad());
            }
            Ok(Timestamp::parse(v).map_err(|_| bad())?.instant())
        };
        let policy_issued = timestamp("policy_issued")?;
        let policy_expires = timestamp("policy_expires")?;
        let issued = timestamp("issued_at")?;
        let expires = timestamp("expires_at")?;
        if policy_issued > issued
            || issued >= expires
            || expires > policy_expires
            || expires != (issued + time::Duration::microseconds(ttl as i64)).min(policy_expires)
        {
            return Err(bad());
        }
        Ok(Self {
            canonical: body.to_vec(),
            value,
            hash: Sha256::digest(body).into(),
            issued,
            expires,
        })
    }
    fn text(&self, key: &str) -> &str {
        self.value[key].as_str().expect("validated metadata")
    }
    pub fn tenant_id(&self) -> &str {
        self.text("tenant_id")
    }
    pub fn gateway_id(&self) -> &str {
        self.text("gateway_id")
    }
    pub fn generation(&self) -> &str {
        self.text("generation")
    }
    pub fn backend_client_leaf(&self) -> &str {
        self.text("backend_client_leaf")
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn metadata_sha256(&self) -> [u8; 32] {
        self.hash
    }
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued
    }
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_vector_and_mutations() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/specification/fixtures/gateway-enrollment-v1.json"
        ))
        .unwrap();
        let body = v["canonical_utf8"].as_str().unwrap();
        let value = GatewayEnrollment::decode(body.as_bytes()).unwrap();
        let hexhash = value
            .metadata_sha256()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hexhash, v["metadata_sha256"].as_str().unwrap());
        assert_eq!(value.canonical_bytes(), body.as_bytes());
        assert!(GatewayEnrollment::decode(format!("{body} ").as_bytes()).is_err());
        assert!(
            GatewayEnrollment::decode(
                body.replace("\"gateway_id\":", "\"extra\":0,\"gateway_id\":")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            GatewayEnrollment::decode(
                body.replace(
                    "\"gateway_id\":",
                    "\"gateway_id\":\"duplicate\",\"gateway_id\":"
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(
            GatewayEnrollment::decode(body.replace("300000000", "0300000000").as_bytes()).is_err()
        );
        assert!(
            GatewayEnrollment::decode(
                body.replace("2026-11-12T23:59:00.000000Z", "2026-11-13T00:01:00.000000Z")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(GatewayEnrollment::decode(&vec![b' '; 4097]).is_err());
    }
}
