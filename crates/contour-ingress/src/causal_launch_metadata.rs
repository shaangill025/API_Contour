//! Canonical CLB1 public metadata. Encoding inputs is not authorization: only
//! a separately checked bound owner may send a seed or start a child.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataError;
/// Data-only inputs. Their source and association with a checked session,
/// bound marker, inspected deployment and one-use journal are not verified here.
pub struct MetadataInputs<'a> {
    pub batch_bytes: u32,
    pub batch_events: u32,
    pub ca_sha256: &'a str,
    pub epoch: u64,
    pub export_credential: &'a str,
    pub export_leaf: &'a str,
    pub generation: &'a str,
    pub launch_slot: &'a str,
    pub launcher_sha256: &'a str,
    pub manifest_sha256: &'a str,
    pub marker_public: &'a str,
    pub nonce: &'a str,
    pub product_credential: &'a str,
    pub product_leaf: &'a str,
    pub queue_bytes: u32,
    pub queue_ttl_ms: u32,
    pub runtime: &'a str,
    pub server_leaf: &'a str,
    pub tenant: &'a str,
}
fn hex(s: &str) -> bool {
    s.len() == 64
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
/// Exact public JSON plus its commitment; no seed, session or launch authority.
pub fn canonical_metadata(x: &MetadataInputs<'_>) -> Result<(Vec<u8>, [u8; 32]), MetadataError> {
    if x.epoch == 0
        || !(1..=500).contains(&x.batch_events)
        || !(512..=1_048_576).contains(&x.batch_bytes)
        || x.queue_bytes < x.batch_bytes.saturating_mul(2)
        || x.queue_bytes > 268_435_456
        || !(1..=86_400_000).contains(&x.queue_ttl_ms)
    {
        return Err(MetadataError);
    }
    if [
        x.export_credential,
        x.nonce,
        x.product_credential,
        x.runtime,
        x.tenant,
    ]
    .iter()
    .any(|x| !uuid(x))
        || [
            x.ca_sha256,
            x.export_leaf,
            x.generation,
            x.launch_slot,
            x.launcher_sha256,
            x.manifest_sha256,
            x.marker_public,
            x.product_leaf,
            x.server_leaf,
        ]
        .iter()
        .any(|x| !hex(x))
        || [x.generation, x.launch_slot, x.launcher_sha256]
            .iter()
            .any(|x| x.bytes().all(|b| b == b'0'))
    {
        return Err(MetadataError);
    }
    let mut m: BTreeMap<&str, Value> = BTreeMap::new();
    for (k, v) in [
        ("ca_sha256", x.ca_sha256),
        ("export_credential", x.export_credential),
        ("export_leaf", x.export_leaf),
        ("generation", x.generation),
        ("launch_slot", x.launch_slot),
        ("launcher_sha256", x.launcher_sha256),
        ("manifest_sha256", x.manifest_sha256),
        ("marker_public", x.marker_public),
        ("nonce", x.nonce),
        ("product_credential", x.product_credential),
        ("product_leaf", x.product_leaf),
        ("runtime", x.runtime),
        ("server_leaf", x.server_leaf),
        ("tenant", x.tenant),
    ] {
        m.insert(k, json!(v));
    }
    m.insert("batch_bytes", json!(x.batch_bytes));
    m.insert("batch_events", json!(x.batch_events));
    m.insert("epoch", json!(x.epoch.to_string()));
    m.insert("profile_id", json!("00000000-0000-4000-8000-000000000503"));
    m.insert("queue_bytes", json!(x.queue_bytes));
    m.insert("queue_ttl_ms", json!(x.queue_ttl_ms));
    m.insert("version", json!(1));
    let body = serde_json::to_vec(&m).map_err(|_| MetadataError)?;
    if body.len() > 16384 {
        return Err(MetadataError);
    }
    let mut hash = Sha256::new();
    hash.update(b"apicontour/causal-launch/1\n");
    hash.update((body.len() as u32).to_be_bytes());
    hash.update(&body);
    let identity: [u8; 32] = hash.finalize().into();
    let mut text = String::with_capacity(64);
    for b in identity {
        use std::fmt::Write;
        write!(&mut text, "{b:02x}").map_err(|_| MetadataError)?;
    }
    m.insert("identity", json!(text));
    let encoded = serde_json::to_vec(&m).map_err(|_| MetadataError)?;
    if encoded.len() > 16384 {
        return Err(MetadataError);
    }
    Ok((encoded, identity))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_vector_matches_node_and_rejects_invalid_bounds() {
        let ca = "66".repeat(32);
        let ex = "11".repeat(32);
        let generation = "22".repeat(32);
        let slot = "88".repeat(32);
        let launch = "99".repeat(32);
        let manifest = "33".repeat(32);
        let marker = "44".repeat(32);
        let product = "55".repeat(32);
        let server = "77".repeat(32);
        let mut x = MetadataInputs {
            batch_bytes: 512,
            batch_events: 1,
            ca_sha256: &ca,
            epoch: u64::MAX,
            export_credential: "00000000-0000-4000-8000-000000000001",
            export_leaf: &ex,
            generation: &generation,
            launch_slot: &slot,
            launcher_sha256: &launch,
            manifest_sha256: &manifest,
            marker_public: &marker,
            nonce: "00000000-0000-4000-8000-000000000002",
            product_credential: "00000000-0000-4000-8000-000000000003",
            product_leaf: &product,
            queue_bytes: 1024,
            queue_ttl_ms: 60000,
            runtime: "00000000-0000-4000-8000-000000000004",
            server_leaf: &server,
            tenant: "00000000-0000-4000-8000-000000000005",
        };
        let (json, id) = canonical_metadata(&x).unwrap();
        assert_eq!(
            id,
            [
                0xd7, 0xde, 0x41, 0xe6, 0x40, 0xd1, 0xb3, 0xc9, 0x1b, 0x96, 0x4b, 0x60, 0xc3, 0xc2,
                0x87, 0x4f, 0x30, 0xdc, 0x8e, 0x86, 0xe4, 0xb5, 0xab, 0x42, 0xee, 0xeb, 0xd0, 0x87,
                0x2b, 0x2e, 0x96, 0xa9
            ]
        );
        assert!(
            std::str::from_utf8(&json)
                .unwrap()
                .contains("\"epoch\":\"18446744073709551615\"")
        );
        x.epoch = 0;
        assert!(canonical_metadata(&x).is_err());
        x.epoch = 1;
        x.queue_bytes = 1023;
        assert!(canonical_metadata(&x).is_err());
    }
}
