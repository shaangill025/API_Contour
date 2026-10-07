use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    AdmissionError, AdmissionInputs, Batch, PolicyKeys, SourceAssignment, Timestamp,
    VerifiedPolicy, validate_admission,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
fn batch() -> Value {
    let fixtures: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../docs/specification/fixtures/batches.json"
    ))
    .unwrap();
    fixtures
        .into_iter()
        .find(|row| row["id"] == "valid_structure")
        .unwrap()["body"]
        .clone()
}
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
fn admit(input: &Value, historical: &Value, current: &Value) -> Result<(), AdmissionError> {
    let historical = verified(historical);
    let current = verified(current);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&historical], &sources)?;
    let batch = Batch::from_wire_json(&serde_json::to_vec(input).unwrap()).unwrap();
    validate_admission(&batch, &inputs, now())
}
#[test]
fn schema_valid_secret_operation_is_rejected() {
    let mut input = batch();
    input["records"][0]["operation"] = json!("SYNTHETIC_SECRET");
    assert_eq!(
        admit(&input, &policy(), &policy()),
        Err(AdmissionError::Scope)
    );
}
fn newer() -> Value {
    let mut value = policy();
    value["revision"] = json!(2);
    value
}
#[test]
fn valid_and_historical_expiry_at_admission() {
    assert_eq!(admit(&batch(), &policy(), &policy()), Ok(()));
    let mut old = policy();
    old["expires_at"] = json!("2026-10-06T12:00:06Z");
    assert_eq!(admit(&batch(), &old, &newer()), Ok(()));
    for timestamp in ["2026-10-06T12:00:05Z", "2026-10-06T12:00:04Z"] {
        old["expires_at"] = json!(timestamp);
        assert_eq!(admit(&batch(), &old, &newer()), Err(AdmissionError::Time));
    }
    let mut old = policy();
    old["issued_at"] = json!("2026-10-06T12:00:06Z");
    assert_eq!(admit(&batch(), &old, &newer()), Err(AdmissionError::Time));
    for field in ["enabled", "expires_at"] {
        let mut current = newer();
        current[field] = if field == "enabled" {
            json!(false)
        } else {
            json!("2026-10-06T12:00:06Z")
        };
        assert_eq!(
            admit(&batch(), &policy(), &current),
            Err(AdmissionError::Time)
        );
    }
    let mut disabled = policy();
    disabled["enabled"] = json!(false);
    assert_eq!(
        admit(&batch(), &disabled, &newer()),
        Err(AdmissionError::Time)
    );
    let mut expired_batch = batch();
    expired_batch["records"][0]["expires_at"] = json!("2026-10-06T12:00:06Z");
    assert_eq!(
        admit(&expired_batch, &policy(), &newer()),
        Err(AdmissionError::Time)
    );
}
#[test]
fn historical_and_current_scopes_both_apply() {
    for field in [
        "approved_names",
        "service_ids",
        "techniques",
        "parser_profiles",
    ] {
        let mut denied = policy();
        denied[field] = json!([]);
        assert_eq!(
            admit(&batch(), &denied, &newer()),
            Err(AdmissionError::Scope),
            "historical {field}"
        );
        denied["revision"] = json!(2);
        assert_eq!(
            admit(&batch(), &policy(), &denied),
            Err(AdmissionError::Scope),
            "current {field}"
        );
    }
    for field in [
        "request_header_names",
        "response_header_names",
        "query_parameter_names",
    ] {
        let mut input = batch();
        input["records"][0][field] = json!(["SYNTHETIC_SECRET"]);
        assert_eq!(
            admit(&input, &policy(), &newer()),
            Err(AdmissionError::Scope),
            "{field}"
        );
    }
    let mut denied = newer();
    denied["techniques"] = json!(["gateway"]);
    // Approved parser cannot disguise the source registry's denied runtime technique.
    assert_eq!(
        admit(&batch(), &policy(), &denied),
        Err(AdmissionError::Scope)
    );
}
#[test]
fn all_recursive_shape_branches_and_depth_are_checked() {
    let secret =
        json!({"kind":"object","fields":{"SYNTHETIC_SECRET":{"kind":"string"}},"additional":null});
    let approved = json!({"kind":"object","fields":{"id":{"kind":"string"}},"additional":null});
    for shape in [
        secret.clone(),
        json!({"kind":"object","fields":{"id":secret},"additional":null}),
        json!({"kind":"object","fields":{},"additional":secret}),
        json!({"kind":"array","items":secret}),
        json!({"kind":"union","alternatives":[approved,secret]}),
    ] {
        let mut input = batch();
        input["records"][0]["structure"] = shape;
        assert_eq!(
            admit(&input, &policy(), &newer()),
            Err(AdmissionError::Scope)
        );
    }
    let mut shallow = newer();
    shallow["depth_limit"] = json!(1);
    assert_eq!(
        admit(&batch(), &policy(), &shallow),
        Err(AdmissionError::Scope)
    );
    shallow["revision"] = json!(1);
    assert_eq!(
        admit(&batch(), &shallow, &newer()),
        Err(AdmissionError::Scope)
    );
}
#[test]
fn tuple_source_and_collector_are_exact() {
    for field in [
        "project_id",
        "service_id",
        "environment_id",
        "deployment_id",
        "source_id",
    ] {
        let mut input = batch();
        input["records"][0][field] = json!(SOURCE);
        if field == "source_id" {
            input["records"][0][field] = json!(ID);
        }
        assert_eq!(
            admit(&input, &policy(), &newer()),
            Err(AdmissionError::Source),
            "{field}"
        );
    }
    for field in ["tenant_id", "collector_id"] {
        let mut input = batch();
        input[field] = json!(SOURCE);
        assert_eq!(
            admit(&input, &policy(), &newer()),
            Err(AdmissionError::Identity)
        );
    }
    let policy = verified(&policy());
    let wrong = [SourceAssignment::new(
        SOURCE,
        [ID, SOURCE, ID, ID, ID, ID],
        "runtime",
        &["http_json_v1"],
    )
    .unwrap()];
    assert_eq!(
        AdmissionInputs::new([ID; 2], &policy, &[&policy], &wrong).unwrap_err(),
        AdmissionError::Identity
    );
    let sources = [SourceAssignment::new(SOURCE, [ID; 6], "runtime", &["other"]).unwrap()];
    let inputs = AdmissionInputs::new([ID; 2], &policy, &[&policy], &sources).unwrap();
    let batch = Batch::from_wire_json(&serde_json::to_vec(&batch()).unwrap()).unwrap();
    assert_eq!(
        validate_admission(&batch, &inputs, now()),
        Err(AdmissionError::Source)
    );
}
#[test]
fn retention_and_revision_guards() {
    let mut current = newer();
    current["queue_ttl_seconds"] = json!(86399);
    assert_eq!(
        admit(&batch(), &policy(), &current),
        Err(AdmissionError::Retention)
    );
    let mut old = policy();
    old["queue_ttl_seconds"] = json!(86399);
    assert_eq!(
        admit(&batch(), &old, &newer()),
        Err(AdmissionError::Retention)
    );
    current["queue_ttl_seconds"] = json!(0);
    assert_eq!(
        admit(&batch(), &policy(), &current),
        Err(AdmissionError::Retention)
    );
    let mut input = batch();
    input["records"][0]["policy_revision"] = json!(3);
    assert_eq!(
        admit(&input, &policy(), &newer()),
        Err(AdmissionError::Revision)
    );
    assert_eq!(
        admit(&batch(), &newer(), &policy()),
        Err(AdmissionError::Revision)
    );
    let mut conflicting = policy();
    conflicting["inspection_bytes"] = json!(0);
    assert_eq!(
        admit(&batch(), &conflicting, &policy()),
        Err(AdmissionError::Revision)
    );
    let current = verified(&policy());
    let whitespace = verified_raw(
        &[b" ".as_slice(), &serde_json::to_vec(&policy()).unwrap()].concat(),
        now(),
    );
    assert_eq!(
        AdmissionInputs::new([ID; 2], &current, &[&whitespace], &[]).unwrap_err(),
        AdmissionError::Revision
    );
    assert_eq!(
        AdmissionInputs::new([ID; 2], &current, &[&current, &current], &[]).unwrap_err(),
        AdmissionError::Revision
    );
}
#[test]
fn closed_routes_and_conservative_denial_overlap() {
    for route in [
        "orders",
        "//orders",
        "/orders/",
        "/orders//x",
        "/orders/.",
        "/orders/..",
        "/orders/%2f",
        "/orders/%7Bid%7D",
        "/orders/\\x",
        "/orders/{other}",
        "/orders/x{id}",
        "/orders/x}",
        "/orders/http:example",
        "/orders/\n",
    ] {
        let mut input = batch();
        input["records"][0]["route_template"] = json!(route);
        assert_eq!(
            admit(&input, &policy(), &newer()),
            Err(AdmissionError::Route),
            "{route:?}"
        );
    }
    for (observed, denied) in [
        ("/admin/{id}", "/admin/{segment}"),
        ("/admin/{segment}", "/admin/{id}"),
        ("/{segment}", "/admin"),
        ("/admin", "/{id}"),
        ("/", "/"),
    ] {
        let mut input = batch();
        input["records"][0]["route_template"] = json!(observed);
        let mut current = newer();
        current["denied_templates"] = json!([denied]);
        assert_eq!(
            admit(&input, &policy(), &current),
            Err(AdmissionError::Route)
        );
        current["revision"] = json!(1);
        assert_eq!(
            admit(&input, &current, &newer()),
            Err(AdmissionError::Route)
        );
    }
    let mut input = batch();
    input["records"][0]["route_template"] = json!("/");
    assert_eq!(admit(&input, &policy(), &newer()), Ok(()));
    input["records"][0]["route_template"] = json!("/unapproved/{id}");
    assert_eq!(
        admit(&input, &policy(), &newer()),
        Err(AdmissionError::Route)
    );
    let mut invalid = newer();
    invalid["denied_templates"] = json!(["/unused/{arbitrary}"]);
    assert_eq!(
        admit(&batch(), &policy(), &invalid),
        Err(AdmissionError::Route)
    );
    invalid["denied_templates"] = json!(["/admin"]);
    assert_eq!(admit(&batch(), &policy(), &invalid), Ok(()));
}
#[test]
fn bounded_registries_and_source_constructor() {
    let base_policy = policy();
    let profiles = (0..128).map(|n| format!("p{n}")).collect::<Vec<_>>();
    let refs = profiles.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(SourceAssignment::new(SOURCE, [ID; 6], "runtime", &refs).is_ok());
    let mut too_many = refs.clone();
    too_many.push("overflow");
    for parsers in [vec![], vec!["x", "x"], vec!["1bad"], too_many] {
        assert_eq!(
            SourceAssignment::new(SOURCE, [ID; 6], "runtime", &parsers).unwrap_err(),
            AdmissionError::Inputs
        );
    }
    assert!(SourceAssignment::new("bad", [ID; 6], "runtime", &["p"]).is_err());
    assert!(SourceAssignment::new(SOURCE, [ID; 6], "wire_label", &["p"]).is_err());
    let policy = verified(&policy());
    assert_eq!(
        AdmissionInputs::new([ID; 2], &policy, &vec![&policy; 501], &[]).unwrap_err(),
        AdmissionError::Inputs
    );
    let duplicates = [source(), source()];
    assert_eq!(
        AdmissionInputs::new([ID; 2], &policy, &[&policy], &duplicates).unwrap_err(),
        AdmissionError::Inputs
    );
    let sources = (0..501)
        .map(|n| {
            SourceAssignment::new(
                &format!("00000000-0000-4000-8000-{n:012x}"),
                [ID; 6],
                "runtime",
                &["p"],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(AdmissionInputs::new([ID; 2], &policy, &[&policy], &sources[..500]).is_ok());
    assert_eq!(
        AdmissionInputs::new([ID; 2], &policy, &[&policy], &sources).unwrap_err(),
        AdmissionError::Inputs
    );
    let policies = (1..=500)
        .map(|revision| {
            let mut value = base_policy.clone();
            value["revision"] = json!(revision);
            verified(&value)
        })
        .collect::<Vec<_>>();
    let historical = policies.iter().collect::<Vec<_>>();
    assert!(AdmissionInputs::new([ID; 2], &policies[499], &historical, &[]).is_ok());
}
#[test]
fn registry_identity_and_safe_diagnostics() {
    let current = verified(&policy());
    assert_eq!(
        AdmissionInputs::new(["bad", ID], &current, &[], &[]).unwrap_err(),
        AdmissionError::Inputs
    );
    for field in ["tenant_id", "collector_id"] {
        let mut value = policy();
        value[field] = json!(SOURCE);
        let other = verified(&value);
        assert_eq!(
            AdmissionInputs::new([ID; 2], &other, &[], &[]).unwrap_err(),
            AdmissionError::Identity
        );
        assert_eq!(
            AdmissionInputs::new([ID; 2], &current, &[&other], &[]).unwrap_err(),
            AdmissionError::Identity
        );
    }
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[], &sources).unwrap();
    let batch = Batch::from_wire_json(&serde_json::to_vec(&batch()).unwrap()).unwrap();
    assert_eq!(
        validate_admission(&batch, &inputs, now()),
        Err(AdmissionError::Revision)
    );
    assert_eq!(format!("{inputs:?}"), "AdmissionInputs");
    assert_eq!(format!("{:?}", sources[0]), "SourceAssignment");
    assert_eq!(AdmissionError::Scope.to_string(), "Scope");
}
