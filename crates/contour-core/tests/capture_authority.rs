use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    AdmissionError, AdmissionInputs, CaptureScope, Completeness, ObservationReason, PolicyKeys,
    SourceAssignment, Timestamp, VerifiedPolicy,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
fn time(text: &str) -> time::OffsetDateTime {
    Timestamp::parse(text).unwrap().instant()
}
fn now() -> time::OffsetDateTime {
    time("2026-10-06T12:00:06Z")
}
fn policy() -> Value {
    json!({"tenant_id":ID,"collector_id":ID,"revision":1,
        "issued_at":"2026-10-06T12:00:00Z","expires_at":"2026-10-06T12:15:00Z",
        "enabled":true,"service_ids":[ID],"techniques":["runtime"],
        "approved_names":["GET","id","quantity"],"denied_templates":[],"inspection_bytes":65536,
        "depth_limit":32,"queue_bytes":268435456,"queue_ttl_seconds":86400,
        "durable_queue_enabled":false,"approved_route_segments":["orders","admin"],"parser_profiles":["http_json_v1"]})
}
fn verified_raw(payload: &[u8], at: time::OffsetDateTime) -> VerifiedPolicy {
    let key = SigningKey::from_bytes(&[7; 32]);
    let keys = PolicyKeys::new(&[("test", key.verifying_key().to_bytes())]).unwrap();
    let signature = key.sign(&[b"apicontour/policy/1\n".as_slice(), payload].concat());
    let envelope = json!({"payload_base64url":URL_SAFE_NO_PAD.encode(payload),"signature_base64url":URL_SAFE_NO_PAD.encode(signature.to_bytes()),"key_id":"test","signature_profile":"ed25519-v1"});
    let identity: Value = serde_json::from_slice(payload).unwrap();
    VerifiedPolicy::from_signed_json(
        &serde_json::to_vec(&envelope).unwrap(),
        &keys,
        identity["tenant_id"].as_str().unwrap(),
        identity["collector_id"].as_str().unwrap(),
        at,
    )
    .unwrap()
}
fn verified(value: &Value) -> VerifiedPolicy {
    verified_raw(
        &serde_json::to_vec(value).unwrap(),
        time(value["issued_at"].as_str().unwrap()),
    )
}
fn source() -> SourceAssignment {
    SourceAssignment::new(SOURCE, [ID; 6], "runtime", &["http_json_v1"]).unwrap()
}

fn scope() -> CaptureScope<'static> {
    CaptureScope {
        source_id: SOURCE,
        workload: [ID; 4],
        parser_profile: "http_json_v1",
        operation: "GET",
        route_template: "/orders/{id}",
        request_header_names: &[],
        response_header_names: &[],
        query_parameter_names: &[],
    }
}
#[test]
fn signed_scope_and_recursive_names_are_checked_before_extraction() {
    let current = verified(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let (revision, obs) = inputs
        .inspect_json(
            &scope(),
            br#"{"id":{"quantity":1,"SECRET":"value"}}"#,
            now(),
        )
        .unwrap();
    assert_eq!(revision, 1);
    assert_eq!(obs.completeness, Completeness::Partial);
    let wire = String::from_utf8(obs.shape.to_wire_json().unwrap()).unwrap();
    assert!(wire.contains("quantity"));
    assert!(!wire.contains("SECRET"));
    let mut bad = scope();
    bad.source_id = ID;
    assert!(matches!(
        inputs.inspect_json(&bad, b"0", now()),
        Err(AdmissionError::Source)
    ));
    bad = scope();
    bad.route_template = "/unknown";
    assert!(matches!(
        inputs.inspect_json(&bad, b"0", now()),
        Err(AdmissionError::Route)
    ));
    bad = scope();
    bad.operation = "SECRET";
    assert!(matches!(
        inputs.inspect_json(&bad, b"0", now()),
        Err(AdmissionError::Scope)
    ));
    bad = scope();
    bad.parser_profile = "other";
    assert!(matches!(
        inputs.inspect_json(&bad, b"0", now()),
        Err(AdmissionError::Scope)
    ));
    assert!(matches!(
        inputs.inspect_json(&scope(), b"0", time("2026-10-06T12:15:00Z")),
        Err(AdmissionError::Time)
    ));
}
#[test]
fn signed_byte_and_depth_limits_and_denied_routes_apply() {
    let mut raw = policy();
    raw["inspection_bytes"] = json!(3);
    raw["depth_limit"] = json!(1);
    raw["denied_templates"] = json!(["/orders/{segment}"]);
    let current = verified(&raw);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    assert!(matches!(
        inputs.inspect_json(&scope(), b"0", now()),
        Err(AdmissionError::Route)
    ));
    let mut allowed = scope();
    allowed.route_template = "/admin";
    for bytes in [b"1234".as_slice(), b"[0]".as_slice()] {
        let (_, obs) = inputs.inspect_json(&allowed, bytes, now()).unwrap();
        assert_eq!(obs.reasons, vec![ObservationReason::Limit]);
    }
}

#[test]
fn disabled_policy_and_assignment_mismatch_reject() {
    let mut raw = policy();
    raw["enabled"] = json!(false);
    let disabled = verified(&raw);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &disabled, &[&disabled], &sources).unwrap();
    assert!(matches!(
        inputs.inspect_json(&scope(), b"0", now()),
        Err(AdmissionError::Time)
    ));
    let current = verified(&policy());
    let other_source =
        [SourceAssignment::new(SOURCE, [ID; 6], "gateway", &["http_json_v1"]).unwrap()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &other_source).unwrap();
    assert!(matches!(
        inputs.inspect_json(&scope(), b"0", now()),
        Err(AdmissionError::Scope)
    ));
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut bad = scope();
    bad.workload[0] = SOURCE;
    assert!(matches!(
        inputs.inspect_json(&bad, b"0", now()),
        Err(AdmissionError::Source)
    ));
}

#[test]
fn denied_deep_field_is_omitted_without_claiming_completeness() {
    let mut raw = policy();
    raw["depth_limit"] = json!(1);
    let current = verified(&raw);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let (_, obs) = inputs
        .inspect_json(
            &scope(),
            br#"{"SECRET":{"nested":{"deeper":"value"}}}"#,
            now(),
        )
        .unwrap();
    assert_eq!(obs.reasons, vec![ObservationReason::Permission]);
    assert_eq!(obs.completeness, Completeness::Partial);
    let wire = String::from_utf8(obs.shape.to_wire_json().unwrap()).unwrap();
    assert!(!wire.contains("SECRET") && !wire.contains("nested") && !wire.contains("value"));
    let over_global = format!("{{\"SECRET\":{}0{}}}", "[".repeat(32), "]".repeat(32));
    let (_, obs) = inputs
        .inspect_json(&scope(), over_global.as_bytes(), now())
        .unwrap();
    assert_eq!(obs.reasons, vec![ObservationReason::Limit]);
}

#[test]
fn retained_array_shapes_respect_signed_depth() {
    for (limit, body) in [
        (1, b"[]".as_slice()),
        (2, b"[1,\"x\"]".as_slice()),
        (2, b"[[]]".as_slice()),
    ] {
        let mut raw = policy();
        raw["depth_limit"] = json!(limit);
        let current = verified(&raw);
        let sources = [source()];
        let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
        let (_, obs) = inputs.inspect_json(&scope(), body, now()).unwrap();
        assert_eq!(obs.reasons, vec![ObservationReason::Limit]);
        assert_eq!(obs.completeness, Completeness::Partial);
    }
}

#[test]
fn adapter_clock_preserves_signed_snapshot_checks_and_revision() {
    use contour_core::InspectionClock;
    use std::time::Duration;
    struct Clock(Option<Duration>);
    impl InspectionClock for Clock {
        fn now(&mut self) -> Option<Duration> {
            self.0
        }
    }
    let mut raw = policy();
    raw["inspection_bytes"] = json!(32);
    raw["depth_limit"] = json!(2);
    let current = verified(&raw);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut clock = Clock(Some(Duration::ZERO));
    let (revision, observation) = inputs
        .inspect_json_with_clock(&scope(), br#"{"id":1,"SECRET":2}"#, now(), &mut clock)
        .unwrap();
    assert_eq!(revision, 1);
    assert_eq!(observation.reasons, vec![ObservationReason::Permission]);
    assert!(
        !String::from_utf8(observation.shape.to_wire_json().unwrap())
            .unwrap()
            .contains("SECRET")
    );
    for body in [
        b"123456789012345678901234567890123".as_slice(),
        b"[[0]]".as_slice(),
    ] {
        assert_eq!(
            inputs
                .inspect_json_with_clock(&scope(), body, now(), &mut clock)
                .unwrap()
                .1
                .reasons,
            vec![ObservationReason::Limit]
        );
    }
    let mut bad = scope();
    bad.operation = "SECRET";
    assert!(matches!(
        inputs.inspect_json_with_clock(&bad, b"0", now(), &mut clock),
        Err(AdmissionError::Scope)
    ));
    assert!(matches!(
        inputs.inspect_json_with_clock(&scope(), b"0", time("2026-10-06T12:15:00Z"), &mut clock),
        Err(AdmissionError::Time)
    ));
    clock.0 = None;
    assert_eq!(
        inputs
            .inspect_json_with_clock(&scope(), b"0", now(), &mut clock)
            .unwrap()
            .1
            .reasons,
        vec![ObservationReason::Limit]
    );
}
