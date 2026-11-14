use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    CausalGrantError as E, CausalGrantKeys, PolicyKeys, Timestamp, VerifiedCausalGrant,
    VerifiedPolicy,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"apicontour/causal-grant/1\n";
const POLICY_DOMAIN: &[u8] = b"apicontour/policy/1\n";
const ID: &str = "00000000-0000-4000-8000-000000000001";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn keys() -> CausalGrantKeys {
    CausalGrantKeys::new(&[("test", key().verifying_key().to_bytes())]).unwrap()
}
fn now() -> time::OffsetDateTime {
    Timestamp::parse("2026-10-07T12:00:00Z").unwrap().instant()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/signed-causal-grant-openssl.json")).unwrap()
}
fn payload() -> Value {
    fixture()["payload"].clone()
}
fn signed(raw: &[u8], domain: &[u8]) -> Value {
    json!({"payload_base64url":URL_SAFE_NO_PAD.encode(raw),"signature_base64url":URL_SAFE_NO_PAD.encode(key().sign(&[domain,raw].concat()).to_bytes()),"key_id":"test","signature_profile":"ed25519-v1"})
}
fn envelope(p: &Value) -> Value {
    signed(&serde_json::to_vec(p).unwrap(), DOMAIN)
}
fn decode(e: &Value) -> Result<VerifiedCausalGrant, E> {
    VerifiedCausalGrant::from_signed_json(&serde_json::to_vec(e).unwrap(), &keys(), now())
}
fn verify(p: &Value) -> Result<VerifiedCausalGrant, E> {
    decode(&envelope(p))
}
#[test]
fn independent_openssl_vector_and_checked_accessors() {
    let f = fixture();
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(f["public_key_base64url"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let keys = CausalGrantKeys::new(&[("openssl-fixture", public)]).unwrap();
    let g = VerifiedCausalGrant::from_signed_json(
        &serde_json::to_vec(&f["envelope"]).unwrap(),
        &keys,
        now(),
    )
    .unwrap();
    assert_eq!(
        [
            g.tenant_id(),
            g.collector_id(),
            g.runtime_id(),
            g.source_id(),
            g.lifecycle_id(),
            g.instance_id()
        ],
        [ID; 6]
    );
    assert_eq!(g.causal_profile(), "nodered_5_0_9_v1");
    assert_eq!(g.profile_sha256(), "ab".repeat(32));
    assert_eq!(g.revision(), 1);
    assert!(g.enabled());
    assert_eq!(g.event_kinds().len(), 4);
    assert_eq!(
        (
            g.max_batch_events(),
            g.max_batch_bytes(),
            g.queue_bytes(),
            g.queue_ttl_seconds()
        ),
        (500, 1048576, 268435456, 86400)
    );
    assert_eq!(g.validate_capture_at(now()), Ok(()));
    assert_eq!(
        format!(
            "{:x}",
            sha2::digest::Output::<Sha256>::from(g.payload_digest())
        ),
        f["payload_sha256"].as_str().unwrap()
    );
    assert_eq!(format!("{g:?}"), "VerifiedCausalGrant");
    assert_eq!(format!("{keys:?}"), "CausalGrantKeys");
}
#[test]
fn signature_precedes_parsing_and_domains_do_not_cross() {
    let mut malformed = signed(b"not json SECRET", DOMAIN);
    assert_eq!(decode(&malformed).unwrap_err(), E::Invalid);
    malformed["payload_base64url"] = json!(URL_SAFE_NO_PAD.encode(b"different SECRET"));
    assert_eq!(decode(&malformed).unwrap_err(), E::Signature);
    let raw = serde_json::to_vec(&payload()).unwrap();
    assert_eq!(
        decode(&signed(&raw, POLICY_DOMAIN)).unwrap_err(),
        E::Signature
    );
    let policy_keys = PolicyKeys::new(&[("test", key().verifying_key().to_bytes())]).unwrap();
    let e = signed(&raw, DOMAIN);
    assert_eq!(
        VerifiedPolicy::from_signed_json(
            &serde_json::to_vec(&e).unwrap(),
            &policy_keys,
            ID,
            ID,
            now()
        )
        .unwrap_err(),
        contour_core::PolicyError::Signature
    );
    let g = decode(&signed(&raw, DOMAIN)).unwrap();
    let spaced = [b" ".as_slice(), &raw].concat();
    let changed = decode(&signed(&spaced, DOMAIN)).unwrap();
    assert_ne!(g.payload_digest(), changed.payload_digest());
    assert_eq!(
        changed.payload_digest().as_slice(),
        Sha256::digest(spaced).as_slice()
    );
}
#[test]
fn envelope_keys_and_crypto_are_strict() {
    assert!(CausalGrantKeys::new(&[]).is_err());
    assert!(CausalGrantKeys::new(&[("", key().verifying_key().to_bytes())]).is_err());
    assert!(
        CausalGrantKeys::new(&[
            ("same", key().verifying_key().to_bytes()),
            ("same", key().verifying_key().to_bytes())
        ])
        .is_err()
    );
    assert!(CausalGrantKeys::new(&[("weak", [0; 32])]).is_err());
    let ids: Vec<String> = (0..9).map(|x| x.to_string()).collect();
    let list: Vec<_> = ids
        .iter()
        .map(|id| (id.as_str(), key().verifying_key().to_bytes()))
        .collect();
    assert!(CausalGrantKeys::new(&list).is_err());
    for (field, value, err) in [
        ("key_id", "unknown", E::Key),
        ("signature_profile", "bad", E::Profile),
        ("payload_base64url", "YQ==", E::Invalid),
        ("signature_base64url", "AA", E::Invalid),
    ] {
        let mut e = envelope(&payload());
        e[field] = json!(value);
        assert_eq!(decode(&e).unwrap_err(), err);
    }
    let mut e = envelope(&payload());
    e["extra"] = json!("SECRET");
    assert_eq!(decode(&e).unwrap_err(), E::Invalid);
    let e = serde_json::to_string(&envelope(&payload()))
        .unwrap()
        .replace(
            "\"key_id\":\"test\"",
            "\"key_id\":\"test\",\"key_id\":\"test\"",
        );
    assert_eq!(
        VerifiedCausalGrant::from_signed_json(e.as_bytes(), &keys(), now()).unwrap_err(),
        E::Invalid
    );
    assert_eq!(
        VerifiedCausalGrant::from_signed_json(&vec![b' '; 1_048_577], &keys(), now()).unwrap_err(),
        E::Size
    );
    let mut e = envelope(&payload());
    let mut sig = URL_SAFE_NO_PAD
        .decode(e["signature_base64url"].as_str().unwrap())
        .unwrap();
    sig[..32].fill(0);
    sig[0] = 1;
    e["signature_base64url"] = json!(URL_SAFE_NO_PAD.encode(sig));
    assert_eq!(decode(&e).unwrap_err(), E::Signature);
    assert!(!format!("{} {:?}", E::Invalid, E::Invalid).contains("SECRET"));
}
#[test]
fn fixtures_strict_payload_and_bounds() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/causal-grants.json"
    ))
    .unwrap();
    for f in fixtures.as_array().unwrap() {
        assert_eq!(
            verify(&f["body"]).is_ok(),
            f["expected"] == "accept",
            "{}",
            f["id"]
        );
    }
    for (field, values) in [
        ("max_batch_events", vec![json!(0), json!(501)]),
        ("max_batch_bytes", vec![json!(0), json!(1048577)]),
        ("queue_bytes", vec![json!(268435457u64)]),
        ("queue_ttl_seconds", vec![json!(0), json!(86401)]),
        ("revision", vec![json!(0), json!("1"), json!(true)]),
    ] {
        for value in values {
            let mut p = payload();
            p[field] = value;
            assert!(verify(&p).is_err(), "{field}");
        }
    }
    let mut p = payload();
    p["revision"] = json!(u64::MAX);
    p["max_batch_events"] = json!(1);
    p["max_batch_bytes"] = json!(1);
    p["queue_ttl_seconds"] = json!(1);
    assert_eq!(verify(&p).unwrap().revision(), u64::MAX);
    let raw = serde_json::to_string(&payload()).unwrap();
    for (a, b) in [
        ("\"revision\":1", "\"revision\":1.0"),
        ("\"revision\":1", "\"revision\":1e0"),
        ("\"revision\":1", "\"revision\":18446744073709551616"),
        ("\"revision\":1", "\"revision\":1,\"revision\":1"),
    ] {
        assert!(decode(&signed(raw.replace(a, b).as_bytes(), DOMAIN)).is_err());
    }
}
#[test]
fn lease_and_disabled_queue_boundaries() {
    let g = verify(&payload()).unwrap();
    assert_eq!(g.validate_at(now()), Ok(()));
    assert_eq!(
        g.validate_at(now() + time::Duration::minutes(15)),
        Err(E::Lease)
    );
    assert_eq!(
        g.validate_at(now() - time::Duration::nanoseconds(1)),
        Err(E::Lease)
    );
    for (field, value) in [("enabled", json!(false)), ("queue_bytes", json!(0))] {
        let mut p = payload();
        p[field] = value;
        let g = verify(&p).unwrap();
        assert_eq!(g.validate_capture_at(now()), Err(E::Disabled));
    }
    for expires in ["2026-10-07T12:00:00Z", "2026-10-07T12:15:01Z"] {
        let mut p = payload();
        p["expires_at"] = json!(expires);
        assert_eq!(verify(&p).unwrap_err(), E::Lease);
    }
}

#[test]
fn malformed_metadata_and_strict_signature_regressions() {
    let raw = serde_json::to_string(&payload()).unwrap();
    for field in [
        "grant_version",
        "tenant_id",
        "collector_id",
        "runtime_id",
        "source_id",
        "lifecycle_id",
        "instance_id",
        "causal_profile",
        "profile_sha256",
        "revision",
        "issued_at",
        "expires_at",
        "enabled",
        "event_kinds",
        "max_batch_events",
        "max_batch_bytes",
        "queue_bytes",
        "queue_ttl_seconds",
    ] {
        let mut p = payload();
        p.as_object_mut().unwrap().remove(field);
        assert!(verify(&p).is_err(), "missing {field}");
    }
    for (needle, replacement) in [
        (
            "\"grant_version\":1",
            "\"grant_version\":1,\"grant_version\":1",
        ),
        ("\"revision\":1", "\"revision\":1.00"),
        ("\"queue_bytes\":268435456", "\"queue_bytes\":2.68435456e8"),
        ("\"enabled\":true", "\"enabled\":1"),
    ] {
        assert!(raw.contains(needle));
        assert_eq!(
            decode(&signed(
                raw.replacen(needle, replacement, 1).as_bytes(),
                DOMAIN
            ))
            .unwrap_err(),
            E::Invalid
        );
    }
    for values in [
        json!([]),
        json!(["root", "delivery", "attempt"]),
        json!(["root", "delivery", "attempt", "loss", "root"]),
        json!(["root", "delivery", "attempt", "LOSS"]),
    ] {
        let mut p = payload();
        p["event_kinds"] = values;
        assert!(verify(&p).is_err());
    }
    for text in [
        "2026-10-07T12:00:00",
        "2026-10-07T12:00:60Z",
        "2026-10-07T12:00:00.1234567890Z",
    ] {
        let mut p = payload();
        p["issued_at"] = json!(text);
        assert!(verify(&p).is_err());
    }
    let mut e = envelope(&payload());
    let mut sig = URL_SAFE_NO_PAD
        .decode(e["signature_base64url"].as_str().unwrap())
        .unwrap();
    sig[32..].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    e["signature_base64url"] = json!(URL_SAFE_NO_PAD.encode(sig));
    assert_eq!(decode(&e).unwrap_err(), E::Signature);
    let mut e = envelope(&payload());
    let signature = e["signature_base64url"].as_str().unwrap().to_owned();
    e["signature_base64url"] = json!(signature + "=");
    assert_eq!(decode(&e).unwrap_err(), E::Invalid);
}

#[test]
fn signed_nanosecond_and_offset_lease_boundaries() {
    let mut p = payload();
    p["expires_at"] = json!("2026-10-07T12:00:00.000000001Z");
    let grant = verify(&p).unwrap();
    assert_eq!(grant.validate_at(now()), Ok(()));
    assert_eq!(
        grant.validate_at(now() + time::Duration::nanoseconds(1)),
        Err(E::Lease)
    );
    p["expires_at"] = json!("2026-10-07T12:15:00.000000001Z");
    assert_eq!(verify(&p).unwrap_err(), E::Lease);
    p["issued_at"] = json!("2026-10-07T05:00:00-07:00");
    p["expires_at"] = json!("2026-10-07T14:15:00+02:00");
    let grant = verify(&p).unwrap();
    assert_eq!(grant.issued_at(), now());
    assert_eq!(grant.expires_at(), now() + time::Duration::minutes(15));
}

#[test]
fn candidate_profile_requires_its_exact_hash_and_preserves_legacy() {
    const CANDIDATE: &str = "a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e";
    let mut p = payload();
    assert!(verify(&p).is_ok()); // Existing 501 accepts a well-formed non-registry hash.
    p["causal_profile"] = json!("nodered_5_0_9_wire_v1");
    assert_eq!(verify(&p).unwrap_err(), E::Semantic);
    p["profile_sha256"] = json!(CANDIDATE);
    assert!(verify(&p).is_ok());
    p["profile_sha256"] = json!("b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510");
    assert_eq!(verify(&p).unwrap_err(), E::Semantic);
    p["causal_profile"] = json!("nodered_5_0_9_v2");
    p["profile_sha256"] = json!(CANDIDATE);
    assert_eq!(verify(&p).unwrap_err(), E::Semantic);
    p["causal_profile"] = json!("nodered_5_0_9_wire_v1");
    p["profile_sha256"] = json!(CANDIDATE.to_uppercase());
    assert_eq!(verify(&p).unwrap_err(), E::Semantic);
}
