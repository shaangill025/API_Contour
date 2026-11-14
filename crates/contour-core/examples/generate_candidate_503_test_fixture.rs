//! Deterministic synthetic test vectors only. Seed [42; 32] is public and must
//! never be used for credentials. Reads only the checked-in synthetic fixture.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

fn main() {
    let legacy: Value = serde_json::from_str(include_str!(
        "../../contour-postgres/tests/fixtures/causal_bridge.json"
    ))
    .unwrap();
    let raw = URL_SAFE_NO_PAD
        .decode(legacy["grant"]["payload_base64url"].as_str().unwrap())
        .unwrap();
    let mut payload: Value = serde_json::from_slice(&raw).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut output = serde_json::Map::new();
    output.insert(
        "test_public_hex".into(),
        json!(
            key.verifying_key()
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    );
    payload["causal_profile"] = json!("nodered_5_0_9_wire_v1");
    payload["profile_sha256"] =
        json!("a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e");
    for (name, change) in [
        ("candidate", None),
        (
            "wrong_tenant",
            Some(("tenant_id", json!("00000000-0000-4000-8000-000000000002"))),
        ),
        ("corrupt_scope", Some(("source_id", json!("invalid")))),
        ("disabled", Some(("enabled", json!(false)))),
        (
            "unknown_502",
            Some(("causal_profile", json!("nodered_5_0_9_v2"))),
        ),
        (
            "cross_hash",
            Some((
                "profile_sha256",
                json!("b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510"),
            )),
        ),
        (
            "legacy_name_candidate_hash",
            Some(("causal_profile", json!("nodered_5_0_9_v1"))),
        ),
    ] {
        let mut p = payload.clone();
        if let Some((field, value)) = change {
            p[field] = value;
        }
        let bytes = serde_json::to_vec(&p).unwrap();
        let signature = key.sign(&[b"apicontour/causal-grant/1\n".as_slice(), &bytes].concat());
        output.insert(name.into(), json!({"key_id":"candidate-test", "payload_base64url":URL_SAFE_NO_PAD.encode(bytes), "signature_base64url":URL_SAFE_NO_PAD.encode(signature.to_bytes()), "signature_profile":"ed25519-v1"}));
    }
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
