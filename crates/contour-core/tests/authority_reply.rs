use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    AuthorityReplyError, MAX_AUTHORITY_REPLY_BYTES, PolicyKeys, Timestamp, check_authority_reply,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::time::Duration;
const ID: &str = "00000000-0000-4000-8000-000000000001";
const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
fn at(s: &str) -> time::OffsetDateTime {
    Timestamp::parse(s).unwrap().instant()
}
fn policy() -> Value {
    json!({"tenant_id":ID,"collector_id":ID,"revision":1,"issued_at":"2026-10-06T12:00:00Z","expires_at":"2026-10-06T12:15:00Z","enabled":true,"service_ids":[ID],"techniques":["runtime"],"approved_names":["GET"],"denied_templates":[],"inspection_bytes":65536,"depth_limit":32,"queue_bytes":268435456,"queue_ttl_seconds":86400,"durable_queue_enabled":false,"approved_route_segments":["orders"],"parser_profiles":["http_json_v1"]})
}
fn envelope(p: &Value) -> Value {
    let key = SigningKey::from_bytes(&[7; 32]);
    let payload = serde_json::to_vec(p).unwrap();
    let sig = key.sign(&[b"apicontour/policy/1\n".as_slice(), &payload].concat());
    json!({"payload_base64url":URL_SAFE_NO_PAD.encode(payload),"signature_base64url":URL_SAFE_NO_PAD.encode(sig.to_bytes()),"key_id":"test","signature_profile":"ed25519-v1"})
}
fn keys() -> PolicyKeys {
    PolicyKeys::new(&[(
        "test",
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    )])
    .unwrap()
}
fn source() -> Value {
    json!({"source_id":SOURCE,"project_id":ID,"service_id":ID,"environment_id":ID,"deployment_id":ID,"technique":"runtime","parser_profiles":["http_json_v1"]})
}
fn reply() -> Value {
    json!({"wire_version":1,"challenge":"nonce","tenant_id":ID,"collector_id":ID,"checked_at":"2026-10-06T12:00:00Z","signed_policy":envelope(&policy()),"sources":[source()]})
}
fn check(v: &Value) -> Result<contour_core::CheckedAuthorityReply, AuthorityReplyError> {
    check_authority_reply(
        &serde_json::to_vec(v).unwrap(),
        "nonce",
        ID,
        ID,
        &[SOURCE.to_owned()],
        &keys(),
        at("2026-10-06T12:00:06Z"),
    )
}
#[test]
fn valid_and_lease_boundaries() {
    let mut v = reply();
    let checked = check(&v).unwrap();
    assert_eq!(checked.lease, Duration::from_secs(900));
    assert_eq!(checked.sources.len(), 1);
    assert_eq!(
        checked.envelope_bytes,
        serde_json::to_vec(&v["signed_policy"]).unwrap().len()
    );
    v["checked_at"] = json!("2026-10-06T12:14:59Z");
    assert_eq!(check(&v).unwrap().lease, Duration::from_secs(1));
    v["checked_at"] = json!("2026-10-06T12:15:00Z");
    assert!(matches!(check(&v), Err(AuthorityReplyError::Invalid)));
}
#[test]
fn rejects_wrong_bindings_and_invalid_assignments() {
    for (key, value) in [
        ("challenge", json!("other")),
        ("tenant_id", json!(SOURCE)),
        ("collector_id", json!(SOURCE)),
        ("wire_version", json!(2)),
    ] {
        let mut v = reply();
        v[key] = value;
        assert!(check(&v).is_err(), "{key}");
    }
    let mut v = reply();
    v["sources"][0]["source_id"] = json!(ID);
    assert!(check(&v).is_err());
    v = reply();
    v["sources"][0]["project_id"] = json!("bad");
    assert!(check(&v).is_err());
    v = reply();
    v["sources"] = json!([source(), source()]);
    assert!(
        check_authority_reply(
            &serde_json::to_vec(&v).unwrap(),
            "nonce",
            ID,
            ID,
            &[SOURCE.to_owned(), ID.to_owned()],
            &keys(),
            at("2026-10-06T12:00:06Z")
        )
        .is_err()
    );
}
#[test]
fn rejects_signature_policy_and_times() {
    let mut v = reply();
    v["signed_policy"]["signature_base64url"] = json!("A".repeat(86));
    assert!(check(&v).is_err());
    let mut p = policy();
    p["enabled"] = json!(false);
    v = reply();
    v["signed_policy"] = envelope(&p);
    assert!(check(&v).is_err());
    v = reply();
    v["checked_at"] = json!("2026-10-06T11:59:59Z");
    assert!(check(&v).is_err());
    assert!(
        check_authority_reply(
            &serde_json::to_vec(&reply()).unwrap(),
            "nonce",
            ID,
            ID,
            &[SOURCE.to_owned()],
            &keys(),
            at("2026-10-06T12:15:00Z")
        )
        .is_err()
    );
}
#[test]
fn exact_body_limit_and_duplicate_fields() {
    let mut bytes = serde_json::to_vec(&reply()).unwrap();
    bytes.resize(MAX_AUTHORITY_REPLY_BYTES, b' ');
    assert!(
        check_authority_reply(
            &bytes,
            "nonce",
            ID,
            ID,
            &[SOURCE.to_owned()],
            &keys(),
            at("2026-10-06T12:00:06Z")
        )
        .is_ok()
    );
    let mut duplicate = serde_json::to_vec(&reply()).unwrap();
    duplicate.splice(1..1, br#""challenge":"nonce", "#.iter().copied());
    assert!(matches!(
        check_authority_reply(
            &duplicate,
            "nonce",
            ID,
            ID,
            &[SOURCE.to_owned()],
            &keys(),
            at("2026-10-06T12:00:06Z")
        ),
        Err(AuthorityReplyError::Invalid)
    ));
}

#[test]
fn rejects_wire_and_bounds() {
    let mut v = reply();
    v["extra"] = json!(1);
    assert!(check(&v).is_err());
    v = reply();
    v["sources"][0]["extra"] = json!(1);
    assert!(check(&v).is_err());
    v = reply();
    v["sources"][0]["parser_profiles"] = json!(["x".repeat(65)]);
    assert!(check(&v).is_err());
    v["sources"][0]["parser_profiles"] = json!(vec!["x"; 129]);
    assert!(check(&v).is_err());
    v = reply();
    v["sources"] = json!(vec![source(); 501]);
    assert!(check(&v).is_err());
    for data in [
        b"{".as_slice(),
        br#"{"wire_version":1,"wire_version":1}"#.as_slice(),
    ] {
        assert!(
            check_authority_reply(
                data,
                "nonce",
                ID,
                ID,
                &[SOURCE.to_owned()],
                &keys(),
                at("2026-10-06T12:00:06Z")
            )
            .is_err()
        );
    }
    assert!(matches!(
        check_authority_reply(
            &vec![b' '; MAX_AUTHORITY_REPLY_BYTES + 1],
            "nonce",
            ID,
            ID,
            &[],
            &keys(),
            at("2026-10-06T12:00:06Z")
        ),
        Err(AuthorityReplyError::Size)
    ));
}
