use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{PolicyError, PolicyKeys, Timestamp, VerifiedPolicy};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const DOMAIN: &[u8] = b"apicontour/policy/1\n";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn now() -> time::OffsetDateTime {
    Timestamp::parse("2026-10-07T12:00:00Z").unwrap().instant()
}
fn policy() -> Value {
    json!({"tenant_id":ID,"collector_id":ID,"revision":1,
        "issued_at":"2026-10-07T12:00:00Z","expires_at":"2026-10-07T12:15:00Z",
        "enabled":true,"service_ids":[ID],"techniques":["runtime"],
        "approved_names":["GET"],"denied_templates":[],"inspection_bytes":65536,
        "depth_limit":32,"queue_bytes":268435456,"queue_ttl_seconds":86400,
        "durable_queue_enabled":false,"approved_route_segments":["api"],"parser_profiles":["json-v1"]})
}
fn signed(payload: &[u8], domain: &[u8]) -> Value {
    let message = [domain, payload].concat();
    json!({"payload_base64url":URL_SAFE_NO_PAD.encode(payload),
        "signature_base64url":URL_SAFE_NO_PAD.encode(key().sign(&message).to_bytes()),
        "key_id":"test","signature_profile":"ed25519-v1"})
}
fn envelope(value: &Value) -> Value {
    signed(&serde_json::to_vec(value).unwrap(), DOMAIN)
}
fn verify(value: &Value) -> bool {
    let keys = PolicyKeys::new(&[("test", key().verifying_key().to_bytes())]).unwrap();
    VerifiedPolicy::from_signed_json(&serde_json::to_vec(value).unwrap(), &keys, ID, ID, now())
        .is_ok()
}
#[test]
fn valid_signed_policy_is_verified() {
    assert!(verify(&envelope(&policy())));
}

#[test]
fn independent_openssl_policy_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/signed-policy-openssl.json")).unwrap();
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["public_key_base64url"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let keys = PolicyKeys::new(&[("openssl-fixture", public)]).unwrap();
    let verified = VerifiedPolicy::from_signed_json(
        &serde_json::to_vec(&fixture["envelope"]).unwrap(),
        &keys,
        ID,
        ID,
        now(),
    )
    .unwrap();
    assert_eq!(verified.revision(), 1);
    assert_eq!(verified.validate_capture_at(now()), Ok(()));
}

#[test]
fn noncanonical_scalar_and_small_order_r_are_signature_errors() {
    let original = envelope(&policy());
    let bytes = URL_SAFE_NO_PAD
        .decode(original["signature_base64url"].as_str().unwrap())
        .unwrap();
    let mut noncanonical = bytes.clone();
    // S equal to the group order L is not a canonical scalar (S must be < L).
    noncanonical[32..].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    let mut small_order = bytes;
    // Compressed Edwards identity (order one) in the R half of the signature.
    small_order[..32].fill(0);
    small_order[0] = 1;
    for signature in [noncanonical, small_order] {
        let mut value = original.clone();
        value["signature_base64url"] = json!(URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            PolicyError::Signature
        );
    }
}

fn decode(bytes: &[u8]) -> Result<VerifiedPolicy, PolicyError> {
    let keys = PolicyKeys::new(&[("test", key().verifying_key().to_bytes())]).unwrap();
    VerifiedPolicy::from_signed_json(bytes, &keys, ID, ID, now())
}
#[test]
fn signature_precedes_parsing_and_binds_raw_bytes() {
    let malformed = signed(b"not json SECRET", DOMAIN);
    assert_eq!(
        decode(&serde_json::to_vec(&malformed).unwrap()).unwrap_err(),
        PolicyError::Invalid
    );
    let mut tampered = malformed;
    tampered["payload_base64url"] = json!(URL_SAFE_NO_PAD.encode(b"not json DIFFERENT"));
    assert_eq!(
        decode(&serde_json::to_vec(&tampered).unwrap()).unwrap_err(),
        PolicyError::Signature
    );
    assert!(!verify(&signed(
        &serde_json::to_vec(&policy()).unwrap(),
        b"other/domain\n"
    )));
    let raw = serde_json::to_vec(&policy()).unwrap();
    let mut changed = signed(&raw, DOMAIN);
    changed["payload_base64url"] = json!(URL_SAFE_NO_PAD.encode([b" ".as_slice(), &raw].concat()));
    assert!(!verify(&changed));
    assert!(verify(&signed(&[b" ".as_slice(), &raw].concat(), DOMAIN)));
}
#[test]
fn envelope_fields_encoding_and_size_are_strict() {
    for field in [
        "payload_base64url",
        "signature_base64url",
        "key_id",
        "signature_profile",
    ] {
        let mut value = envelope(&policy());
        value.as_object_mut().unwrap().remove(field);
        assert!(!verify(&value));
        let value = serde_json::to_string(&envelope(&policy())).unwrap();
        let duplicate = value.replacen(
            &format!("\"{field}\":"),
            &format!("\"{field}\":\"SECRET\",\"{field}\":"),
            1,
        );
        assert_eq!(
            decode(duplicate.as_bytes()).unwrap_err(),
            PolicyError::Invalid
        );
    }
    for (field, invalid) in [
        ("signature_profile", "ed25519-v2"),
        ("key_id", "unknown"),
        ("payload_base64url", "="),
        ("signature_base64url", "AA"),
        ("unknown", "SECRET"),
    ] {
        let mut value = envelope(&policy());
        value[field] = json!(invalid);
        assert!(!verify(&value));
    }
    for field in ["payload_base64url", "signature_base64url"] {
        let mut value = envelope(&policy());
        value[field] = json!(format!("{}=", value[field].as_str().unwrap()));
        assert!(!verify(&value));
    }
    assert_eq!(
        decode(&vec![b' '; 1_048_577]).unwrap_err(),
        PolicyError::Size
    );
    assert_eq!(
        decode(&vec![b' '; 1_048_576]).unwrap_err(),
        PolicyError::Invalid
    );
    let text = serde_json::to_string(&envelope(&policy())).unwrap();
    let escaped = text.replacen("\"key_id\":", "\"\\u006bey_id\":\"SECRET\",\"key_id\":", 1);
    assert_eq!(
        decode(escaped.as_bytes()).unwrap_err(),
        PolicyError::Invalid
    );
}
#[test]
fn all_payload_fields_are_required_and_duplicates_unknowns_rejected() {
    for field in policy().as_object().unwrap().keys() {
        let mut value = policy();
        value.as_object_mut().unwrap().remove(field);
        assert!(!verify(&envelope(&value)), "{field}");
        let text = serde_json::to_string(&policy()).unwrap();
        let duplicate = text.replacen(
            &format!("\"{field}\":"),
            &format!("\"{field}\":{},\"{field}\":", policy()[field]),
            1,
        );
        assert!(!verify(&signed(duplicate.as_bytes(), DOMAIN)), "{field}");
    }
    let mut value = policy();
    value["unknown"] = json!("SECRET");
    assert!(!verify(&envelope(&value)));
    let text = serde_json::to_string(&policy()).unwrap();
    let duplicate = text.replacen(
        "\"tenant_id\":",
        &format!("\"\\u0074enant_id\":\"{ID}\",\"tenant_id\":"),
        1,
    );
    assert!(!verify(&signed(duplicate.as_bytes(), DOMAIN)));
}
#[test]
fn policy_resource_bounds_and_syntax() {
    for (field, invalid) in [
        ("revision", json!(0)),
        ("revision", json!(-1)),
        ("revision", json!(1.5)),
        ("inspection_bytes", json!(65537)),
        ("depth_limit", json!(0)),
        ("depth_limit", json!(33)),
        ("queue_bytes", json!(268435457)),
        ("queue_ttl_seconds", json!(86401)),
        ("techniques", json!(["untrusted"])),
        ("service_ids", json!(["bad"])),
        ("parser_profiles", json!(["1bad"])),
        ("parser_profiles", json!(["x", "x"])),
        ("approved_route_segments", json!(["x", "x"])),
        ("approved_names", json!([""])),
        ("approved_names", json!(["x".repeat(65)])),
        ("denied_templates", json!(["x".repeat(257)])),
        ("enabled", json!(1)),
        ("durable_queue_enabled", json!("false")),
    ] {
        let mut value = policy();
        value[field] = invalid;
        assert!(!verify(&envelope(&value)), "{field}");
    }
    for (field, count, item) in [
        ("service_ids", 200, ID),
        ("techniques", 16, "runtime"),
        ("approved_names", 4096, "x"),
        ("denied_templates", 1024, "/x"),
        ("approved_route_segments", 4096, "x"),
        ("parser_profiles", 128, "x"),
    ] {
        let mut value = policy();
        value[field] = json!(
            (0..count)
                .map(
                    |n| if ["approved_route_segments", "parser_profiles"].contains(&field) {
                        format!("x{n}")
                    } else {
                        item.to_owned()
                    }
                )
                .collect::<Vec<_>>()
        );
        assert!(verify(&envelope(&value)), "{field} boundary");
        value[field].as_array_mut().unwrap().push(json!(item));
        assert!(!verify(&envelope(&value)), "{field} overflow");
    }
    let mut value = policy();
    value["approved_names"] = json!(["é".repeat(64)]);
    value["revision"] = json!(u64::MAX);
    assert!(verify(&envelope(&value)));
    let mut text = serde_json::to_string(&value).unwrap();
    text = text.replace(&u64::MAX.to_string(), "18446744073709551616");
    assert!(!verify(&signed(text.as_bytes(), DOMAIN)));
}
#[test]
fn identity_lease_disabled_and_safe_accessors() {
    let bytes = serde_json::to_vec(&envelope(&policy())).unwrap();
    let verified = decode(&bytes).unwrap();
    assert_eq!(verified.tenant_id(), ID);
    assert_eq!(verified.collector_id(), ID);
    assert_eq!(verified.revision(), 1);
    assert!(verified.enabled());
    assert_eq!(verified.validate_at(verified.issued_at()), Ok(()));
    assert_eq!(
        verified.validate_at(verified.expires_at()),
        Err(PolicyError::Lease)
    );
    assert_eq!(
        verified.validate_at(now() - time::Duration::nanoseconds(1)),
        Err(PolicyError::Lease)
    );
    assert_eq!(format!("{verified:?}"), "VerifiedPolicy");
    for (field, invalid) in [
        ("tenant_id", "00000000-0000-4000-8000-000000000002"),
        ("collector_id", "00000000-0000-4000-8000-000000000002"),
        ("tenant_id", "00000000-0000-4000-8000-00000000000A"),
        ("expires_at", "2026-10-07T12:15:00.000000001Z"),
        ("expires_at", "2026-10-07T12:00:00Z"),
        ("issued_at", "2026-10-07T12:00:01Z"),
    ] {
        let mut value = policy();
        value[field] = json!(invalid);
        assert!(!verify(&envelope(&value)), "{field}");
    }
    let keys = PolicyKeys::new(&[("test", key().verifying_key().to_bytes())]).unwrap();
    assert_eq!(
        VerifiedPolicy::from_signed_json(&bytes, &keys, "invalid", ID, now()).unwrap_err(),
        PolicyError::Identity
    );
    let mut value = policy();
    value["enabled"] = json!(false);
    let disabled = decode(&serde_json::to_vec(&envelope(&value)).unwrap()).unwrap();
    assert!(!disabled.enabled());
    assert_eq!(
        disabled.validate_capture_at(now()),
        Err(PolicyError::Disabled)
    );
    assert_eq!(verified.validate_capture_at(now()), Ok(()));
}
#[test]
fn keyring_is_bounded_unique_and_rejects_weak_keys() {
    let public = key().verifying_key().to_bytes();
    for entries in [
        vec![],
        vec![("", public)],
        vec![("x", public), ("x", public)],
        vec![("x", [0; 32])],
        vec![("x", std::array::from_fn(|n| u8::from(n == 0)))],
        vec![("x", public); 9],
    ] {
        assert_eq!(PolicyKeys::new(&entries).unwrap_err(), PolicyError::Key);
    }
    let long = "x".repeat(65);
    assert!(PolicyKeys::new(&[(&long, public)]).is_err());
    let ids = (0..8).map(|n| format!("key{n}")).collect::<Vec<_>>();
    assert!(
        PolicyKeys::new(
            &ids.iter()
                .map(|id| (id.as_str(), public))
                .collect::<Vec<_>>()
        )
        .is_ok()
    );
    let wrong = PolicyKeys::new(&[(
        "test",
        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
    )])
    .unwrap();
    assert_eq!(
        VerifiedPolicy::from_signed_json(
            &serde_json::to_vec(&envelope(&policy())).unwrap(),
            &wrong,
            ID,
            ID,
            now()
        )
        .unwrap_err(),
        PolicyError::Signature
    );
    assert_eq!(format!("{wrong:?}"), "PolicyKeys");
}
#[test]
fn independent_rfc8032_vector() {
    // RFC 8032 section 7.1, TEST 1: fixed published public key and empty-message signature.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        std::array::from_fn(|n| u8::from_str_radix(&text[n * 2..n * 2 + 2], 16).unwrap())
    }
    let public = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    ed25519_dalek::VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(b"", &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
    let keys = PolicyKeys::new(&[("rfc", public)]).unwrap();
    let value = json!({"key_id":"rfc","signature_profile":"ed25519-v1",
        "payload_base64url":URL_SAFE_NO_PAD.encode(b"{}"),"signature_base64url":URL_SAFE_NO_PAD.encode(signature)});
    assert_eq!(
        VerifiedPolicy::from_signed_json(
            &serde_json::to_vec(&value).unwrap(),
            &keys,
            ID,
            ID,
            now()
        )
        .unwrap_err(),
        PolicyError::Signature
    );
}
