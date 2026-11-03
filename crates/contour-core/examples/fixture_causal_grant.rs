//! Verify the independent synthetic grant fixture; no capture authority is implied.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{CausalGrantKeys, Timestamp, VerifiedCausalGrant};
fn main() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/signed-causal-grant-openssl.json"
    ))
    .unwrap();
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["public_key_base64url"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let keys = CausalGrantKeys::new(&[("openssl-fixture", public)]).unwrap();
    let now = Timestamp::parse("2026-10-07T12:00:00Z").unwrap().instant();
    let grant = VerifiedCausalGrant::from_signed_json(
        &serde_json::to_vec(&fixture["envelope"]).unwrap(),
        &keys,
        now,
    )
    .unwrap();
    for byte in grant.payload_digest() {
        print!("{byte:02x}");
    }
    println!();
}
