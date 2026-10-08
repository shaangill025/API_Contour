use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    AdmissionError, AdmissionInputs, Batch, BatchError, CheckedRecord, Completeness,
    ExtractionPolicy, Kind, Observation, ObservationReason, PolicyKeys, RecordDraft,
    RecordMetadata, Shape, SourceAssignment, Timestamp, UnknownReason, VerifiedPolicy,
    extract_json, validate_admission,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
fn fixture() -> Value {
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
fn timestamp(text: &str) -> Timestamp {
    Timestamp::parse(text).unwrap()
}
fn metadata(record: &Value) -> RecordMetadata<'_> {
    let text = |field| record[field].as_str().unwrap();
    RecordMetadata {
        record_id: text("record_id"),
        source_id: text("source_id"),
        workload: [
            text("project_id"),
            text("service_id"),
            text("environment_id"),
            text("deployment_id"),
        ],
        protocol: text("protocol"),
        direction: text("direction"),
        visibility: text("visibility"),
        operation: text("operation"),
        route_template: text("route_template"),
        route_uncertain: record["route_uncertain"].as_bool().unwrap(),
        parser_profile: text("parser_profile"),
        policy_revision: record["policy_revision"].as_u64().unwrap(),
        count: record["count"].as_u64().unwrap(),
        first_seen: timestamp(text("first_seen")),
        last_seen: timestamp(text("last_seen")),
        sample_numerator: record["sample_numerator"].as_u64().unwrap(),
        sample_denominator: record["sample_denominator"].as_u64().unwrap(),
        status_code: record["status_code"]
            .as_u64()
            .map(|status| u16::try_from(status).unwrap()),
        request_header_names: &[],
        response_header_names: &[],
        query_parameter_names: &[],
    }
}
fn observation(record: &Value) -> Observation {
    Observation {
        shape: Shape::from_wire_json(&serde_json::to_vec(&record["structure"]).unwrap()).unwrap(),
        completeness: Completeness::Complete,
        reasons: vec![],
    }
}
fn draft(record: &Value) -> RecordDraft {
    RecordDraft::from_observation(metadata(record), observation(record)).unwrap()
}
fn declare(draft: RecordDraft, record: &Value) -> CheckedRecord {
    draft
        .declare_queue_times(
            timestamp(record["queued_at"].as_str().unwrap()),
            timestamp(record["expires_at"].as_str().unwrap()),
        )
        .unwrap()
}
fn assemble(records: Vec<CheckedRecord>) -> Result<Batch, BatchError> {
    Batch::assemble(ID, [ID; 2], timestamp("2026-10-06T12:00:05Z"), records)
}

#[test]
fn constructor_matches_frozen_wire_and_digest() {
    let input = fixture();
    let record = &input["records"][0];
    let constructed = assemble(vec![declare(draft(record), record)]).unwrap();
    let decoded = Batch::from_wire_json(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(
        constructed.to_wire_json().unwrap(),
        decoded.to_wire_json().unwrap()
    );
    assert_eq!(
        constructed.request_digest_bytes().unwrap(),
        decoded.request_digest_bytes().unwrap()
    );
    assert_eq!(
        constructed.request_digest().unwrap(),
        decoded.request_digest().unwrap()
    );
}

#[test]
fn extraction_values_never_enter_record_and_debug_is_redacted() {
    let input = fixture();
    let record = &input["records"][0];
    let policy = ExtractionPolicy::object(
        vec![
            ("id".into(), ExtractionPolicy::default()),
            ("quantity".into(), ExtractionPolicy::default()),
        ],
        None,
    )
    .unwrap();
    let observed = extract_json(
        br#"{"id":"SYNTHETIC_BUSINESS_VALUE","quantity":12}"#,
        &policy,
    );
    let metadata = metadata(record);
    assert_eq!(format!("{metadata:?}"), "RecordMetadata");
    let draft = RecordDraft::from_observation(metadata, observed).unwrap();
    assert_eq!(format!("{draft:?}"), "RecordDraft");
    let checked = declare(draft, record);
    assert_eq!(format!("{checked:?}"), "CheckedRecord");
    let batch = assemble(vec![checked]).unwrap();
    assert!(
        !String::from_utf8(batch.to_wire_json().unwrap())
            .unwrap()
            .contains("SYNTHETIC_BUSINESS_VALUE")
    );
}

#[test]
fn distinct_dimensions_and_each_name_list_preserve_field_mapping() {
    let mut input = fixture();
    let record = &mut input["records"][0];
    for (index, field) in [
        "project_id",
        "service_id",
        "environment_id",
        "deployment_id",
    ]
    .iter()
    .enumerate()
    {
        record[*field] = json!(format!("00000000-0000-4000-8000-{:012x}", index + 10));
    }
    record["protocol"] = json!("kafka");
    record["direction"] = json!("publish");
    record["route_uncertain"] = json!(true);
    record["status_code"] = Value::Null;
    record["request_header_names"] = json!(["request_name"]);
    record["response_header_names"] = json!(["response_name"]);
    record["query_parameter_names"] = json!(["query_name"]);
    let mut info = metadata(record);
    info.request_header_names = &["request_name"];
    info.response_header_names = &["response_name"];
    info.query_parameter_names = &["query_name"];
    let draft = RecordDraft::from_observation(info, observation(record)).unwrap();
    let constructed = assemble(vec![declare(draft, record)]).unwrap();
    let decoded = Batch::from_wire_json(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(
        constructed.to_wire_json().unwrap(),
        decoded.to_wire_json().unwrap()
    );
    assert_eq!(
        constructed.request_digest_bytes().unwrap(),
        decoded.request_digest_bytes().unwrap()
    );
}

#[test]
fn metadata_semantics_are_shared_with_wire_validation() {
    let record = fixture()["records"][0].clone();
    for (field, value) in [
        ("record_id", json!("00000000-0000-4000-8000-00000000000A")),
        ("source_id", json!("SYNTHETIC_SECRET")),
        ("service_id", json!("bad")),
        ("protocol", json!("HTTP")),
        ("direction", json!("other")),
        ("visibility", json!("other")),
        ("operation", json!("")),
        ("route_template", json!("/orders?SYNTHETIC_SECRET")),
        ("parser_profile", json!("9bad")),
        ("policy_revision", json!(0)),
        ("count", json!(0)),
        ("count", json!(1_000_000_001u64)),
        ("sample_numerator", json!(0)),
        ("sample_numerator", json!(2)),
        ("sample_denominator", json!(1_000_001)),
        ("status_code", json!(99)),
        ("status_code", json!(600)),
        ("first_seen", json!("2026-10-06T12:00:06Z")),
    ] {
        let mut changed = record.clone();
        changed[field] = value;
        let error =
            RecordDraft::from_observation(metadata(&changed), observation(&changed)).unwrap_err();
        assert_eq!(error, BatchError::Semantic, "{field}");
        assert_eq!(error.to_string(), "Semantic");
        let mut wire = fixture();
        wire["records"][0] = changed;
        assert!(Batch::from_wire_json(&serde_json::to_vec(&wire).unwrap()).is_err());
    }
    let mut maximum = record.clone();
    maximum["count"] = json!(1_000_000_000);
    maximum["policy_revision"] = json!(u64::MAX);
    maximum["sample_numerator"] = json!(1_000_000);
    maximum["sample_denominator"] = json!(1_000_000);
    maximum["status_code"] = Value::Null;
    assert!(RecordDraft::from_observation(metadata(&maximum), observation(&maximum)).is_ok());
}

#[test]
fn copied_text_and_lists_have_exact_bounds() {
    let record = fixture()["records"][0].clone();
    for (field, limit) in [
        ("operation", 32),
        ("route_template", 256),
        ("parser_profile", 64),
    ] {
        for (size, valid) in [(limit, true), (limit + 1, false)] {
            let mut changed = record.clone();
            changed[field] = json!("a".repeat(size));
            assert_eq!(
                RecordDraft::from_observation(metadata(&changed), observation(&changed)).is_ok(),
                valid
            );
        }
    }
    let unique = (0..129)
        .map(|index| format!("n{index}"))
        .collect::<Vec<_>>();
    let names = unique.iter().map(String::as_str).collect::<Vec<_>>();
    for column in 0..3 {
        for (size, valid) in [(128, true), (129, false)] {
            let mut input = metadata(&record);
            match column {
                0 => input.request_header_names = &names[..size],
                1 => input.response_header_names = &names[..size],
                _ => input.query_parameter_names = &names[..size],
            }
            assert_eq!(
                RecordDraft::from_observation(input, observation(&record)).is_ok(),
                valid
            );
        }
    }
    for names in [vec!["x", "x"], vec![""]] {
        let mut input = metadata(&record);
        input.request_header_names = &names;
        assert_eq!(
            RecordDraft::from_observation(input, observation(&record)).unwrap_err(),
            BatchError::Semantic
        );
    }
    for (size, valid) in [(64, true), (65, false)] {
        let name = "🦀".repeat(size);
        let names = [name.as_str()];
        let mut input = metadata(&record);
        input.query_parameter_names = &names;
        assert_eq!(
            RecordDraft::from_observation(input, observation(&record)).is_ok(),
            valid
        );
    }
}

#[test]
fn observation_consistency_is_not_trusted_from_public_fields() {
    let record = fixture()["records"][0].clone();
    for (shape, completeness, reasons, valid) in [
        (
            Shape::unknown(UnknownReason::Limit),
            Completeness::Complete,
            vec![],
            false,
        ),
        (
            Shape::unknown(UnknownReason::Limit),
            Completeness::Partial,
            vec![],
            false,
        ),
        (
            Shape::unknown(UnknownReason::Limit),
            Completeness::Partial,
            vec![ObservationReason::Limit],
            true,
        ),
        (
            Shape::unknown(UnknownReason::Malformed),
            Completeness::Unavailable,
            vec![ObservationReason::Malformed],
            true,
        ),
        (
            Shape::unknown(UnknownReason::Empty),
            Completeness::Complete,
            vec![],
            true,
        ),
        (
            Shape::primitive(Kind::String).unwrap(),
            Completeness::Complete,
            vec![ObservationReason::Permission],
            false,
        ),
        (
            Shape::unknown(UnknownReason::Limit),
            Completeness::Partial,
            vec![ObservationReason::Limit; 2],
            false,
        ),
        (
            Shape::unknown(UnknownReason::Limit),
            Completeness::Partial,
            vec![ObservationReason::Limit; 9],
            false,
        ),
    ] {
        let observed = Observation {
            shape,
            completeness,
            reasons,
        };
        assert_eq!(
            RecordDraft::from_observation(metadata(&record), observed).is_ok(),
            valid
        );
    }
    let mut input = metadata(&record);
    input.visibility = "operation";
    assert_eq!(
        RecordDraft::from_observation(input, observation(&record)).unwrap_err(),
        BatchError::Semantic
    );
}

#[test]
fn declared_times_are_preserved_and_rechecked_at_batch_assembly() {
    let record = fixture()["records"][0].clone();
    let queued = "2026-10-06T12:00:05.000000000+00:00";
    let expiry = "2026-10-07T12:00:05Z";
    let checked = draft(&record)
        .declare_queue_times(timestamp(queued), timestamp(expiry))
        .unwrap();
    assert_eq!(checked.queued_at().as_str(), queued);
    assert_eq!(checked.expires_at().as_str(), expiry);
    let encoded: Value =
        serde_json::from_slice(&assemble(vec![checked]).unwrap().to_wire_json().unwrap()).unwrap();
    assert_eq!(encoded["records"][0]["queued_at"], queued);
    assert_eq!(encoded["records"][0]["expires_at"], expiry);
    for (queued, expiry) in [
        ("2026-10-06T12:00:05Z", "2026-10-06T12:00:04Z"),
        ("2026-10-06T12:00:05Z", "2026-10-07T12:00:05.000000001Z"),
    ] {
        assert_eq!(
            draft(&record)
                .declare_queue_times(timestamp(queued), timestamp(expiry))
                .unwrap_err(),
            BatchError::Semantic
        );
    }
    let future = draft(&record)
        .declare_queue_times(timestamp("2026-10-06T12:00:06Z"), timestamp(expiry))
        .unwrap();
    assert_eq!(assemble(vec![future]).unwrap_err(), BatchError::Semantic);
    let expired = draft(&record)
        .declare_queue_times(
            timestamp("2026-10-06T12:00:00Z"),
            timestamp("2026-10-06T12:00:04Z"),
        )
        .unwrap();
    assert_eq!(assemble(vec![expired]).unwrap_err(), BatchError::Semantic);
}

fn records(number: usize, large: bool) -> Vec<CheckedRecord> {
    let original = fixture()["records"][0].clone();
    let owned_names = (0..128)
        .map(|index| format!("{index:03}{}", "🦀".repeat(61)))
        .collect::<Vec<_>>();
    let names = owned_names.iter().map(String::as_str).collect::<Vec<_>>();
    (0..number)
        .map(|index| {
            let mut record = original.clone();
            record["record_id"] = json!(format!("00000000-0000-4000-8000-{index:012x}"));
            let mut input = metadata(&record);
            if large {
                input.request_header_names = &names;
                input.response_header_names = &names;
                input.query_parameter_names = &names;
            }
            declare(
                RecordDraft::from_observation(input, observation(&record)).unwrap(),
                &record,
            )
        })
        .collect()
}
#[test]
fn assembly_enforces_identity_uniqueness_count_and_normalized_bytes() {
    assert_eq!(assemble(vec![]).unwrap_err(), BatchError::Semantic);
    assert_eq!(
        assemble(records(501, false)).unwrap_err(),
        BatchError::Semantic
    );
    assert_eq!(assemble(records(500, false)).unwrap().record_count(), 500);
    let record = fixture()["records"][0].clone();
    assert_eq!(
        assemble(vec![
            declare(draft(&record), &record),
            declare(draft(&record), &record)
        ])
        .unwrap_err(),
        BatchError::Semantic
    );
    for (batch_id, identity) in [("bad", [ID; 2]), (ID, [ID, "SYNTHETIC_SECRET"])] {
        assert_eq!(
            Batch::assemble(
                batch_id,
                identity,
                timestamp("2026-10-06T12:00:05Z"),
                records(1, false)
            )
            .unwrap_err(),
            BatchError::Semantic
        );
    }
    assert!(
        assemble(records(8, true))
            .unwrap()
            .to_wire_json()
            .unwrap()
            .len()
            <= 1_048_576
    );
    assert_eq!(assemble(records(12, true)).unwrap_err(), BatchError::Size);
}

#[test]
fn nul_control_and_unicode_names_roundtrip_without_normalization() {
    let record = fixture()["records"][0].clone();
    let names = ["nul\0name", "control\nname", "é", "e\u{301}"];
    let shape = Shape::object(
        names
            .iter()
            .map(|name| ((*name).into(), Shape::primitive(Kind::String).unwrap()))
            .collect(),
        None,
    )
    .unwrap();
    let mut input = metadata(&record);
    input.request_header_names = &names;
    let draft = RecordDraft::from_observation(
        input,
        Observation {
            shape,
            completeness: Completeness::Complete,
            reasons: vec![],
        },
    )
    .unwrap();
    let batch = assemble(vec![declare(draft, &record)]).unwrap();
    let bytes = batch.to_wire_json().unwrap();
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(wire["records"][0]["request_header_names"], json!(names));
    for name in names {
        assert!(
            wire["records"][0]["structure"]["fields"]
                .get(name)
                .is_some()
        );
    }
    assert_eq!(
        Batch::from_wire_json(&bytes)
            .unwrap()
            .request_digest()
            .unwrap(),
        batch.request_digest().unwrap()
    );
}

fn approved_policy() -> VerifiedPolicy {
    let payload = serde_json::to_vec(&json!({
        "tenant_id":ID,"collector_id":ID,"revision":1,
        "issued_at":"2026-10-06T12:00:00Z","expires_at":"2026-10-06T12:15:00Z",
        "enabled":true,"service_ids":[ID],"techniques":["runtime"],"approved_names":["GET","id","quantity"],
        "denied_templates":[],"inspection_bytes":65536,"depth_limit":32,"queue_bytes":268435456,"queue_ttl_seconds":86400,
        "durable_queue_enabled":false,"approved_route_segments":["orders"],"parser_profiles":["http_json_v1"]
    })).unwrap();
    let signer = SigningKey::from_bytes(&[7; 32]); // Inert local test seed only.
    let keys = PolicyKeys::new(&[("construction", signer.verifying_key().to_bytes())]).unwrap();
    let signature = signer.sign(&[b"apicontour/policy/1\n".as_slice(), &payload].concat());
    let envelope = serde_json::to_vec(&json!({"key_id":"construction","signature_profile":"ed25519-v1","payload_base64url":URL_SAFE_NO_PAD.encode(&payload),"signature_base64url":URL_SAFE_NO_PAD.encode(signature.to_bytes())})).unwrap();
    VerifiedPolicy::from_signed_json(
        &envelope,
        &keys,
        ID,
        ID,
        timestamp("2026-10-06T12:00:05Z").instant(),
    )
    .unwrap()
}
#[test]
fn syntactic_construction_still_requires_full_privacy_admission() {
    let policy = approved_policy();
    let sources = [SourceAssignment::new(SOURCE, [ID; 6], "runtime", &["http_json_v1"]).unwrap()];
    let inputs = AdmissionInputs::new([ID; 2], &policy, &[&policy], &sources).unwrap();
    let now = timestamp("2026-10-06T12:00:06Z").instant();
    let mut record = fixture()["records"][0].clone();
    assert_eq!(
        validate_admission(
            &assemble(vec![declare(draft(&record), &record)]).unwrap(),
            &inputs,
            now
        ),
        Ok(())
    );
    record["operation"] = json!("SYNTHETIC_SECRET");
    assert_eq!(
        validate_admission(
            &assemble(vec![declare(draft(&record), &record)]).unwrap(),
            &inputs,
            now
        ),
        Err(AdmissionError::Scope)
    );
    record["operation"] = json!("GET");
    record["structure"]["fields"]["SYNTHETIC_SECRET"] = json!({"kind":"string"});
    assert_eq!(
        validate_admission(
            &assemble(vec![declare(draft(&record), &record)]).unwrap(),
            &inputs,
            now
        ),
        Err(AdmissionError::Scope)
    );
}
