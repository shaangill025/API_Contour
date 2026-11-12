//! Data-only CLB2 encoding. A valid descriptor never establishes receiver authority.
use crate::{MetadataError, MetadataInputs, canonical_metadata};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Additional receiver fields; their provenance and enrollment are not verified here.
pub struct ReceiverMetadataInputs<'a> {
    pub base: MetadataInputs<'a>,
    pub artifact_sha256: &'a str,
    pub gateway_backend_leaf: &'a str,
    pub gateway_generation: &'a str,
    pub gateway_id: &'a str,
    pub receiver_backend_leaf: &'a str,
    pub receiver_enrollment_commitment: &'a str,
    pub receiver_evidence_credential: &'a str,
    pub receiver_evidence_leaf: &'a str,
}

fn hex(s: &str, size: usize) -> bool {
    s.len() == size
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
fn nonzero(s: &str) -> bool {
    s.bytes().any(|b| b != b'0')
}

/// Encode a closed canonical descriptor and its domain-separated identity.
/// Input validation does not authenticate claims, mounts, certificates or peers.
pub fn canonical_receiver_metadata(
    x: &ReceiverMetadataInputs<'_>,
) -> Result<(Vec<u8>, [u8; 32]), MetadataError> {
    if !uuid(x.gateway_id)
        || !uuid(x.receiver_evidence_credential)
        || !hex(x.gateway_generation, 32)
        || !nonzero(x.gateway_generation)
        || [
            x.artifact_sha256,
            x.gateway_backend_leaf,
            x.receiver_backend_leaf,
            x.receiver_enrollment_commitment,
            x.receiver_evidence_leaf,
        ]
        .iter()
        .any(|s| !hex(s, 64))
        || !nonzero(x.artifact_sha256)
        || !nonzero(x.receiver_enrollment_commitment)
        || !nonzero(x.base.manifest_sha256)
        || x.receiver_backend_leaf != x.base.server_leaf
    {
        return Err(MetadataError);
    }
    let leaves = [
        x.base.product_leaf,
        x.base.export_leaf,
        x.base.server_leaf,
        x.receiver_evidence_leaf,
        x.gateway_backend_leaf,
    ];
    for (i, leaf) in leaves.iter().enumerate() {
        if leaves[..i].contains(leaf) {
            return Err(MetadataError);
        }
    }
    let credentials = [
        x.base.product_credential,
        x.base.export_credential,
        x.receiver_evidence_credential,
    ];
    for (i, credential) in credentials.iter().enumerate() {
        if credentials[..i].contains(credential) {
            return Err(MetadataError);
        }
    }
    // Reuse the unchanged CLB1 field validators and original queue ceilings.
    let (encoded, _) = canonical_metadata(&x.base)?;
    let mut map: std::collections::BTreeMap<String, Value> =
        serde_json::from_slice(&encoded).map_err(|_| MetadataError)?;
    map.remove("identity");
    for (key, value) in [
        ("artifact_sha256", x.artifact_sha256),
        ("gateway_backend_leaf", x.gateway_backend_leaf),
        ("gateway_generation", x.gateway_generation),
        ("gateway_id", x.gateway_id),
        ("receiver_backend_leaf", x.receiver_backend_leaf),
        (
            "receiver_enrollment_commitment",
            x.receiver_enrollment_commitment,
        ),
        (
            "receiver_evidence_credential",
            x.receiver_evidence_credential,
        ),
        ("receiver_evidence_leaf", x.receiver_evidence_leaf),
        ("profile_id", "00000000-0000-4000-8000-000000000504"),
        ("profile_name", "nodered_5_0_9_receiver_v1"),
    ] {
        map.insert(key.into(), json!(value));
    }
    map.insert("version".into(), json!(2));
    let body = serde_json::to_vec(&map).map_err(|_| MetadataError)?;
    if body.len() > 16384 {
        return Err(MetadataError);
    }
    let mut hash = Sha256::new();
    hash.update(b"apicontour/causal-receiver-launch/2\n");
    hash.update((body.len() as u32).to_be_bytes());
    hash.update(&body);
    let identity: [u8; 32] = hash.finalize().into();
    let mut text = String::with_capacity(64);
    for byte in identity {
        use std::fmt::Write;
        write!(&mut text, "{byte:02x}").map_err(|_| MetadataError)?;
    }
    map.insert("identity".into(), json!(text));
    let result = serde_json::to_vec(&map).map_err(|_| MetadataError)?;
    if result.len() > 16384 {
        return Err(MetadataError);
    }
    Ok((result, identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(v: &Value) -> Result<(Vec<u8>, [u8; 32]), MetadataError> {
        let s = |key: &str| v[key].as_str().unwrap();
        let base = MetadataInputs {
            batch_bytes: v["batch_bytes"].as_u64().unwrap() as u32,
            batch_events: v["batch_events"].as_u64().unwrap() as u32,
            ca_sha256: s("ca_sha256"),
            epoch: s("epoch").parse().unwrap(),
            export_credential: s("export_credential"),
            export_leaf: s("export_leaf"),
            generation: s("generation"),
            launch_slot: s("launch_slot"),
            launcher_sha256: s("launcher_sha256"),
            manifest_sha256: s("manifest_sha256"),
            marker_public: s("marker_public"),
            nonce: s("nonce"),
            product_credential: s("product_credential"),
            product_leaf: s("product_leaf"),
            queue_bytes: v["queue_bytes"].as_u64().unwrap() as u32,
            queue_ttl_ms: v["queue_ttl_ms"].as_u64().unwrap() as u32,
            runtime: s("runtime"),
            server_leaf: s("server_leaf"),
            tenant: s("tenant"),
        };
        canonical_receiver_metadata(&ReceiverMetadataInputs {
            base,
            artifact_sha256: s("artifact_sha256"),
            gateway_backend_leaf: s("gateway_backend_leaf"),
            gateway_generation: s("gateway_generation"),
            gateway_id: s("gateway_id"),
            receiver_backend_leaf: s("receiver_backend_leaf"),
            receiver_enrollment_commitment: s("receiver_enrollment_commitment"),
            receiver_evidence_credential: s("receiver_evidence_credential"),
            receiver_evidence_leaf: s("receiver_evidence_leaf"),
        })
    }
    fn vector() -> (Value, String, String) {
        let shared: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/receiver504-bootstrap/vector.json"
        ))
        .unwrap();
        let canonical = shared["canonical"].as_str().unwrap().to_owned();
        let identity = shared["identity"].as_str().unwrap().to_owned();
        (
            serde_json::from_str(&canonical).unwrap(),
            canonical,
            identity,
        )
    }
    #[test]
    fn shared_node_vector_and_u64_boundaries() {
        let (mut input, expected, identity) = vector();
        let (bytes, digest) = encode(&input).unwrap();
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            identity
        );
        input["epoch"] = json!("1");
        assert!(encode(&input).is_ok());
        input["epoch"] = json!("0");
        assert!(encode(&input).is_err());
    }
    #[test]
    fn invalid_receiver_scope_purpose_and_bounds_are_rejected() {
        let (input, _, _) = vector();
        for (field, invalid) in [
            ("gateway_id", "bad".to_owned()),
            (
                "gateway_id",
                format!("{}\n", input["gateway_id"].as_str().unwrap()),
            ),
            ("gateway_generation", "a".repeat(64)),
            ("gateway_generation", "0".repeat(32)),
            ("gateway_generation", format!("{}\n", "a".repeat(31))),
            ("generation", "a".repeat(32)),
            ("artifact_sha256", "0".repeat(64)),
            ("artifact_sha256", "a".repeat(16385)),
            ("manifest_sha256", "0".repeat(64)),
            ("receiver_enrollment_commitment", "0".repeat(64)),
            ("receiver_backend_leaf", "f".repeat(64)),
            (
                "receiver_evidence_leaf",
                input["product_leaf"].as_str().unwrap().to_owned(),
            ),
            (
                "gateway_backend_leaf",
                input["export_leaf"].as_str().unwrap().to_owned(),
            ),
            (
                "receiver_evidence_credential",
                input["product_credential"].as_str().unwrap().to_owned(),
            ),
        ] {
            let mut changed = input.clone();
            changed[field] = json!(invalid);
            assert!(encode(&changed).is_err(), "accepted {field}");
        }
        for (field, invalid) in [
            ("batch_bytes", 511),
            ("batch_events", 0),
            ("queue_bytes", 1),
            ("queue_ttl_ms", 86400001),
        ] {
            let mut changed = input.clone();
            changed[field] = json!(invalid);
            assert!(encode(&changed).is_err(), "accepted {field}");
        }
    }
}
