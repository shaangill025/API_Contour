use contour_core::{Batch, BatchError, Timestamp};
use serde_json::{Value, json};

fn fixtures() -> Vec<Value> {
    serde_json::from_slice(include_bytes!(
        "../../../docs/specification/fixtures/batches.json"
    ))
    .unwrap()
}
#[test]
fn authority_projection_is_minimal_borrowed_and_preserves_batch() {
    let input = valid();
    let batch = decode(&input).unwrap();
    let digest = batch.request_digest().unwrap();
    let mut requests = batch.authority_requests();
    assert_eq!(requests.len(), batch.record_count());
    let request = requests.next().unwrap();
    assert_eq!(request.source_id(), input["records"][0]["source_id"]);
    assert_eq!(request.revision(), 1);
    assert_eq!(
        request.queued_at(),
        Timestamp::parse(input["records"][0]["queued_at"].as_str().unwrap())
            .unwrap()
            .instant()
    );
    assert!(requests.next().is_none());
    assert_eq!(batch.request_digest().unwrap(), digest);
}
fn valid() -> Value {
    fixtures()
        .into_iter()
        .find(|row| row["id"] == "valid_structure")
        .unwrap()["body"]
        .clone()
}
fn decode(value: &Value) -> Result<Batch, BatchError> {
    Batch::from_wire_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn committed_batch_fixtures() {
    for fixture in fixtures() {
        assert_eq!(
            decode(&fixture["body"]).is_ok(),
            fixture["expected"] == "accept",
            "{}",
            fixture["id"]
        );
    }
}

#[test]
fn nullable_status_is_required_and_round_trips() {
    let mut input = valid();
    input["records"][0]["status_code"] = Value::Null;
    let batch = decode(&input).unwrap();
    assert_eq!(
        decode(&serde_json::from_slice(&batch.to_wire_json().unwrap()).unwrap())
            .unwrap()
            .request_digest()
            .unwrap(),
        batch.request_digest().unwrap()
    );
    input["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("status_code");
    assert_eq!(decode(&input).unwrap_err(), BatchError::Invalid);
}

#[test]
fn unknown_duplicate_trailing_and_errors_are_safe() {
    let input = serde_json::to_string(&valid()).unwrap();
    let duplicate = input.replacen("\"batch_id\":", "\"batch_id\":\"SECRET\",\"batch_id\":", 1);
    let escaped = input.replacen(
        "\"batch_id\":",
        "\"\\u0062atch_id\":\"SECRET\",\"batch_id\":",
        1,
    );
    let nested = input.replacen(
        "\"status_code\":200",
        "\"status_code\":null,\"status_code\":200",
        1,
    );
    let shape_duplicate = input.replacen(
        "\"quantity\":{",
        "\"quantity\":{\"kind\":\"null\"},\"quantity\":{",
        1,
    );
    for text in [
        duplicate,
        escaped,
        nested,
        shape_duplicate,
        format!("{input} null"),
        "null".into(),
        "[]".into(),
    ] {
        let error = Batch::from_wire_json(text.as_bytes()).unwrap_err();
        assert_eq!(error, BatchError::Invalid);
        assert_eq!(error.to_string(), "Invalid");
        assert!(!format!("{error:?}").contains("SECRET"));
    }
    let mut data = valid();
    data["records"][0]["unknown"] = json!("SECRET");
    assert_eq!(decode(&data).unwrap_err(), BatchError::Invalid);
    data = valid();
    data["records"][0]["operation"] = json!("SECRET");
    assert_eq!(format!("{:?}", decode(&data).unwrap()), "Batch");
}

#[test]
fn bounds_and_semantic_invariants() {
    for (field, invalid) in [
        ("record_id", json!("00000000-0000-4000-8000-00000000000A")),
        ("protocol", json!("HTTP")),
        ("direction", json!("other")),
        ("operation", json!("")),
        ("route_template", json!("/x?SECRET")),
        ("route_template", json!("/x#SECRET")),
        ("parser_profile", json!("9bad")),
        ("parser_profile", json!("x\n")),
        ("policy_revision", json!(0)),
        ("count", json!(0)),
        ("count", json!(1_000_000_001u64)),
        ("sample_numerator", json!(0)),
        ("sample_denominator", json!(1_000_001)),
        ("status_code", json!(99)),
        ("status_code", json!(600)),
        ("visibility", json!("other")),
        ("visibility", json!("operation")),
        ("completeness", json!("other")),
        ("completeness", json!("partial")),
        ("reasons", json!(["limit"])),
        ("reasons", json!(["clock_skew", "clock_skew"])),
        ("reasons", json!(["other"])),
        ("request_header_names", json!(["x", "x"])),
        ("response_header_names", json!([""])),
        ("query_parameter_names", json!(["😀".repeat(65)])),
        ("first_seen", json!("2026-10-06T12:00:06Z")),
        ("queued_at", json!("2026-10-06T12:00:06Z")),
        ("expires_at", json!("2026-10-06T12:00:04Z")),
        ("expires_at", json!("2026-10-07T12:00:06Z")),
    ] {
        let mut input = valid();
        input["records"][0][field] = invalid;
        assert!(decode(&input).is_err(), "{field}");
    }
    for (field, max) in [("operation", 32), ("route_template", 256)] {
        let mut input = valid();
        input["records"][0][field] = json!("😀".repeat(max));
        assert!(decode(&input).is_ok());
        input["records"][0][field] = json!("😀".repeat(max + 1));
        assert!(decode(&input).is_err());
    }
    for field in [
        "request_header_names",
        "response_header_names",
        "query_parameter_names",
    ] {
        let mut input = valid();
        input["records"][0][field] = json!((0..128).map(|i| i.to_string()).collect::<Vec<_>>());
        assert!(decode(&input).is_ok());
        input["records"][0][field]
            .as_array_mut()
            .unwrap()
            .push(json!("extra"));
        assert_eq!(decode(&input).unwrap_err(), BatchError::Invalid);
    }
    let mut input = valid();
    input["records"] = json!([]);
    assert_eq!(decode(&input).unwrap_err(), BatchError::Semantic);
    input = valid();
    let record = input["records"][0].clone();
    input["records"].as_array_mut().unwrap().push(record);
    assert_eq!(decode(&input).unwrap_err(), BatchError::Semantic);
    input = valid();
    input["records"][0]["reasons"] = json!(vec!["sampled"; 9]);
    assert_eq!(decode(&input).unwrap_err(), BatchError::Invalid);
}

#[test]
fn exact_metadata_numbers_normalize_and_nullable_is_typed() {
    let input = serde_json::to_string(&valid()).unwrap();
    let decimals = input
        .replace("\"wire_version\":1", "\"wire_version\":1.0")
        .replace("\"count\":12", "\"count\":1200e-2")
        .replace("\"status_code\":200", "\"status_code\":2e2");
    let expected = Batch::from_wire_json(input.as_bytes())
        .unwrap()
        .request_digest()
        .unwrap();
    assert_eq!(
        Batch::from_wire_json(decimals.as_bytes())
            .unwrap()
            .request_digest()
            .unwrap(),
        expected
    );
    for token in ["true", "200.1", "-200", "18446744073709551616"] {
        assert!(
            Batch::from_wire_json(
                input
                    .replace("\"status_code\":200", &format!("\"status_code\":{token}"))
                    .as_bytes()
            )
            .is_err()
        );
    }
    let mut value = valid();
    value["records"][0]["policy_revision"] = json!(u64::MAX);
    assert!(decode(&value).is_ok());
}

#[test]
fn admission_times_have_explicit_inclusive_skew_and_exclusive_expiry() {
    let batch = decode(&valid()).unwrap();
    let created = Timestamp::parse("2026-10-06T12:00:05Z").unwrap().instant();
    assert!(
        batch
            .validate_at(created - time::Duration::minutes(5))
            .is_ok()
    );
    assert_eq!(
        batch.validate_at(created - time::Duration::minutes(5) - time::Duration::nanoseconds(1)),
        Err(BatchError::AdmissionTime)
    );
    let expires = Timestamp::parse("2026-10-07T12:00:05Z").unwrap().instant();
    assert!(
        batch
            .validate_at(expires - time::Duration::nanoseconds(1))
            .is_ok()
    );
    assert_eq!(batch.validate_at(expires), Err(BatchError::AdmissionTime));
    assert_eq!(
        batch.validate_at(expires + time::Duration::minutes(6)),
        Err(BatchError::AdmissionTime)
    );
}

#[test]
fn digest_normalizes_object_order_and_preserves_arrays_and_timestamp_text() {
    let input = valid();
    let batch = decode(&input).unwrap();
    let expected = batch.request_digest().unwrap();
    // Independently computed with Python hashlib and sorted compact fixture JSON.
    assert_eq!(
        expected,
        "b255b40f1473896fb764a41f795be943d87da2547fed5ea8bd7d6877b5a4fa0b"
    );
    let pretty = serde_json::to_string_pretty(&input).unwrap();
    assert_eq!(
        Batch::from_wire_json(pretty.as_bytes())
            .unwrap()
            .request_digest()
            .unwrap(),
        expected
    );
    let object = input.as_object().unwrap();
    let reverse = format!(
        "{{{}}}",
        object
            .iter()
            .rev()
            .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        Batch::from_wire_json(reverse.as_bytes())
            .unwrap()
            .request_digest()
            .unwrap(),
        expected
    );
    let mut changed = input.clone();
    changed["created_at"] = json!("2026-10-06T12:00:05+00:00");
    assert_ne!(
        decode(&changed).unwrap().request_digest().unwrap(),
        expected
    );
    let mut names = input.clone();
    names["records"][0]["request_header_names"] = json!(["a", "b"]);
    let before = decode(&names).unwrap().request_digest().unwrap();
    names["records"][0]["request_header_names"] = json!(["b", "a"]);
    assert_ne!(decode(&names).unwrap().request_digest().unwrap(), before);
    let mut records = input.clone();
    let mut second = records["records"][0].clone();
    second["record_id"] = json!("00000000-0000-4000-8000-000000000003");
    records["records"].as_array_mut().unwrap().push(second);
    let before = decode(&records).unwrap().request_digest().unwrap();
    records["records"].as_array_mut().unwrap().reverse();
    assert_ne!(decode(&records).unwrap().request_digest().unwrap(), before);
    assert_eq!(batch.record_count(), 1);
    assert_eq!(batch.batch_id(), input["batch_id"].as_str().unwrap());
    assert_eq!(batch.tenant_id(), input["tenant_id"].as_str().unwrap());
    assert_eq!(
        batch.collector_id(),
        input["collector_id"].as_str().unwrap()
    );
}

#[test]
fn digest_covers_every_envelope_and_record_field() {
    let base = valid();
    let expected = decode(&base).unwrap().request_digest().unwrap();
    for field in [
        "batch_id",
        "tenant_id",
        "collector_id",
        "created_at",
        "records",
    ] {
        let mut changed = base.clone();
        if field == "created_at" {
            changed[field] = json!("2026-10-06T12:00:06Z");
        } else if field == "records" {
            changed[field][0]["count"] = json!(13);
        } else {
            changed[field] = json!("00000000-0000-0000-0000-000000000003");
        }
        assert_ne!(
            decode(&changed).unwrap().request_digest().unwrap(),
            expected,
            "{field}"
        );
    }
    for field in base["records"][0].as_object().unwrap().keys() {
        let mut changed = base.clone();
        let record = &mut changed["records"][0];
        record[field] = match field.as_str() {
            "record_id" | "project_id" | "service_id" | "environment_id" | "deployment_id"
            | "source_id" => json!("00000000-0000-0000-0000-000000000003"),
            "protocol" => json!("grpc"),
            "direction" => json!("request"),
            "operation" => json!("POST"),
            "route_template" => json!("/other"),
            "route_uncertain" => json!(true),
            "parser_profile" => json!("other"),
            "policy_revision" => json!(2),
            "visibility" => {
                record["structure"] = json!({"kind":"unknown","reason":"unsupported"});
                record["completeness"] = json!("partial");
                record["reasons"] = json!(["unsupported"]);
                json!("operation")
            }
            "completeness" => {
                record["reasons"] = json!(["sampled"]);
                json!("partial")
            }
            "reasons" => json!(["sampled"]),
            "structure" => json!({"kind":"null"}),
            "count" => json!(13),
            "first_seen" => json!("2026-10-06T11:59:59Z"),
            "last_seen" => json!("2026-10-06T12:00:04Z"),
            "sample_numerator" => {
                record["sample_denominator"] = json!(2);
                json!(2)
            }
            "sample_denominator" => json!(2),
            "status_code" => Value::Null,
            "request_header_names" | "response_header_names" | "query_parameter_names" => {
                json!(["safe"])
            }
            "queued_at" => {
                record["expires_at"] = json!("2026-10-07T12:00:04Z");
                json!("2026-10-06T12:00:04Z")
            }
            "expires_at" => json!("2026-10-07T12:00:04Z"),
            _ => panic!("missing mutation for {field}"),
        };
        assert_ne!(
            decode(&changed).unwrap().request_digest().unwrap(),
            expected,
            "{field}"
        );
    }
}

#[test]
fn size_limit_precedes_serde_for_adversarial_inputs() {
    for prefix in [
        b"{\"created_at\":\"\\u0031".as_slice(),
        b"{\"count\":1",
        b"{\"records\":[{",
    ] {
        let mut input = prefix.to_vec();
        input.resize(1_048_577, b'1');
        assert_eq!(Batch::from_wire_json(&input).unwrap_err(), BatchError::Size);
    }
    let mut input = serde_json::to_vec(&valid()).unwrap();
    input.resize(1_048_576, b' ');
    assert!(Batch::from_wire_json(&input).is_ok());
    input.push(b' ');
    assert_eq!(Batch::from_wire_json(&input).unwrap_err(), BatchError::Size);
}

#[test]
fn bounded_record_counts_and_normalized_output_limit() {
    let mut input = valid();
    let template = input["records"][0].clone();
    input["records"] = json!(
        (0..500)
            .map(|i| {
                let mut record = template.clone();
                record["record_id"] = json!(format!("00000000-0000-0000-0000-{i:012x}"));
                record
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(decode(&input).unwrap().record_count(), 500);
    input["records"].as_array_mut().unwrap().push(template);
    assert_eq!(decode(&input).unwrap_err(), BatchError::Invalid);
    input["records"].as_array_mut().unwrap().pop();
    for record in input["records"].as_array_mut().unwrap() {
        record["route_template"] = json!("😀".repeat(200));
        record["request_header_names"] = json!(["😀".repeat(64)]);
    }
    let science = |value: &Value| {
        serde_json::to_string(value)
            .unwrap()
            .replace("\"policy_revision\":1", "\"policy_revision\":1e19")
    };
    // Integral exponent spellings expand during normalization; tune valid name padding.
    let before = science(&input).len();
    let count = (1_045_000 - before) / 258;
    for index in 0..count {
        input["records"][index]["response_header_names"] = json!(["😀".repeat(64)]);
    }
    let text = science(&input);
    assert!(text.len() <= 1_048_576);
    assert_eq!(
        Batch::from_wire_json(text.as_bytes()).unwrap_err(),
        BatchError::Size
    );
}

#[test]
fn complete_evidence_cannot_contain_incomplete_unknown_nodes() {
    for reason in ["unsupported", "limit", "malformed", "encrypted"] {
        let mut input = valid();
        input["records"][0]["structure"]["fields"]["quantity"] =
            json!({"kind":"unknown","reason":reason});
        assert_eq!(decode(&input).unwrap_err(), BatchError::Semantic);
    }
    let mut input = valid();
    input["records"][0]["structure"] =
        json!({"kind":"array","items":{"kind":"unknown","reason":"empty"}});
    assert!(decode(&input).is_ok());
}
