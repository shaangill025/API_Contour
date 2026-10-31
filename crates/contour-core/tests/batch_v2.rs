use contour_core::{Batch, BatchError, BatchV2, OriginWitness};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn fixtures() -> Vec<Value> {
    serde_json::from_slice(include_bytes!(
        "../../../docs/specification/fixtures/batches-v2.json"
    ))
    .unwrap()
}
fn valid() -> Value {
    fixtures().remove(0)["body"].clone()
}
fn decode(input: &Value) -> Result<BatchV2, BatchError> {
    BatchV2::from_wire_json(&serde_json::to_vec(input).unwrap())
}

#[test]
fn fixtures_and_both_witnesses_round_trip_without_authority() {
    for fixture in fixtures() {
        let result = decode(&fixture["body"]);
        assert_eq!(
            result.is_ok(),
            fixture["expected"] == "accept",
            "{}",
            fixture["id"]
        );
        if let Ok(batch) = result {
            let wire = batch.to_wire_json().unwrap();
            let again = BatchV2::from_wire_json(&wire).unwrap();
            assert_eq!(again.to_wire_json().unwrap(), wire);
            assert_eq!(
                again.request_digest_bytes().unwrap(),
                batch.request_digest_bytes().unwrap()
            );
            assert_eq!(batch.record_count(), 1);
            assert_eq!(
                batch.records()[0].record_id(),
                "00000000-0000-4000-8000-000000000001"
            );
            assert_eq!(
                batch.records()[0].source_id(),
                "00000000-0000-4000-8000-000000000002"
            );
            assert_eq!(
                batch.records()[0].workload(),
                ["00000000-0000-4000-8000-000000000001"; 4]
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&batch.records()[0].record_wire_json().unwrap())
                    .unwrap(),
                fixture["body"]["records"][0]["record"]
            );
        }
    }
    let batch = decode(&valid()).unwrap();
    assert!(matches!(
        batch.records()[0].origin_witness(),
        OriginWitness::DownstreamMtlsLeafSha256V1 { .. }
    ));
    let mut other = valid();
    other["records"][0]["origin_witness"] = json!({"kind":"unattributed"});
    assert!(matches!(
        decode(&other).unwrap().records()[0].origin_witness(),
        OriginWitness::Unattributed
    ));
}

#[test]
fn digest_binds_complete_v2_and_uses_independent_domain() {
    let original = valid();
    let batch = decode(&original).unwrap();
    assert_eq!(
        batch.request_digest().unwrap(),
        "d3a8f1b43d3f4a1e6c7b9256112717ed94bbd0e130c9ad993c3a338b56caca1b"
    );
    let mut canonical: Value = serde_json::from_slice(&batch.to_wire_json().unwrap()).unwrap();
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).unwrap();
    let v2: [u8; 32] = Sha256::digest([b"apicontour/batch/2\n".as_slice(), &bytes].concat()).into();
    let v1_domain: [u8; 32] =
        Sha256::digest([b"apicontour/batch/1\n".as_slice(), &bytes].concat()).into();
    assert_eq!(batch.request_digest_bytes().unwrap(), v2);
    assert_ne!(v1_domain, v2);
    let ordinary = serde_json::to_string(&original).unwrap();
    let first = format!(
        "\"kind\":\"downstream_mtls_leaf_sha256_v1\",\"leaf_sha256\":\"{}\"",
        "ab".repeat(32)
    );
    let reversed = format!(
        "\"leaf_sha256\":\"{}\",\"kind\":\"downstream_mtls_leaf_sha256_v1\"",
        "ab".repeat(32)
    );
    assert!(ordinary.contains(&first));
    let reordered = ordinary.replacen(&first, &reversed, 1);
    assert_eq!(
        BatchV2::from_wire_json(reordered.as_bytes())
            .unwrap()
            .request_digest_bytes()
            .unwrap(),
        v2
    );
    let mut changed = original.clone();
    changed["records"][0]["origin_witness"]["leaf_sha256"] = json!("cd".repeat(32));
    assert_ne!(
        batch.request_digest_bytes().unwrap(),
        decode(&changed).unwrap().request_digest_bytes().unwrap()
    );
    changed = original.clone();
    changed["records"][0]["origin_witness"] = json!({"kind":"unattributed"});
    assert_ne!(
        batch.request_digest_bytes().unwrap(),
        decode(&changed).unwrap().request_digest_bytes().unwrap()
    );
    changed = original.clone();
    changed["records"][0]["record"]["source_id"] = json!("00000000-0000-4000-8000-000000000003");
    assert_ne!(
        batch.request_digest_bytes().unwrap(),
        decode(&changed).unwrap().request_digest_bytes().unwrap()
    );
    changed = original.clone();
    changed["batch_id"] = json!("00000000-0000-4000-8000-000000000003");
    assert_ne!(
        batch.request_digest_bytes().unwrap(),
        decode(&changed).unwrap().request_digest_bytes().unwrap()
    );
    for field in ["tenant_id", "collector_id"] {
        changed = original.clone();
        changed[field] = json!("00000000-0000-4000-8000-000000000003");
        assert_ne!(
            batch.request_digest_bytes().unwrap(),
            decode(&changed).unwrap().request_digest_bytes().unwrap()
        );
    }
    for field in [
        "project_id",
        "service_id",
        "environment_id",
        "deployment_id",
    ] {
        changed = original.clone();
        changed["records"][0]["record"][field] = json!("00000000-0000-4000-8000-000000000003");
        assert_ne!(
            batch.request_digest_bytes().unwrap(),
            decode(&changed).unwrap().request_digest_bytes().unwrap()
        );
    }
    assert!(Batch::from_wire_json(&batch.to_wire_json().unwrap()).is_err());
}

#[test]
fn strict_witness_wrapper_and_record_parsing_rejects_duplicates_and_extras() {
    let input = serde_json::to_string(&valid()).unwrap();
    let texts = [
        input.replacen(
            "\"origin_witness\":",
            "\"origin_witness\":null,\"origin_witness\":",
            1,
        ),
        input.replacen(
            "\"leaf_sha256\":",
            "\"leaf_sha256\":\"SECRET\",\"leaf_sha256\":",
            1,
        ),
        input.replacen(
            "\"kind\":\"downstream_mtls_leaf_sha256_v1\"",
            "\"kind\":\"unattributed\",\"kind\":\"downstream_mtls_leaf_sha256_v1\"",
            1,
        ),
        input.replacen(
            "\"source_id\":",
            "\"source_id\":\"SECRET\",\"source_id\":",
            1,
        ),
        input.replacen(
            "\"quantity\":{",
            "\"quantity\":{\"kind\":\"null\"},\"quantity\":{",
            1,
        ),
        input.replacen(
            "\"origin_witness\":",
            "\"\\u006frigin_witness\":null,\"origin_witness\":",
            1,
        ),
        format!("{input} null"),
    ];
    for text in texts {
        let error = BatchV2::from_wire_json(text.as_bytes()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    for mutation in [
        json!({"kind":"downstream_mtls_leaf_sha256_v1","leaf_sha256":"aa","verified":true}),
        json!({"kind":"unattributed","verified":true}),
        json!({"kind":"unattributed","leaf_sha256":"aa"}),
        json!({"kind":"unattributed","leaf_sha256":null}),
        json!({"kind":"downstream_mtls_leaf_sha256_v1","leaf_sha256":null}),
        json!({"kind":"Downstream_mtls_leaf_sha256_v1","leaf_sha256":"ab".repeat(32)}),
        Value::Null,
    ] {
        let mut v = valid();
        v["records"][0]["origin_witness"] = mutation;
        assert!(decode(&v).is_err());
    }
    for value in [
        "ab".repeat(31),
        "ab".repeat(33),
        "AB".repeat(32),
        format!("{}g", "a".repeat(63)),
        format!("{}\n", "a".repeat(64)),
    ] {
        let mut v = valid();
        v["records"][0]["origin_witness"]["leaf_sha256"] = json!(value);
        assert!(decode(&v).is_err());
    }
    let mut v = valid();
    v["records"][0]["forged_verified"] = json!(true);
    assert!(decode(&v).is_err());
    v = valid();
    v["records"][0]["record"]["forged_verified"] = json!(true);
    assert!(decode(&v).is_err());
    v = valid();
    v["records"][0]["record"]
        .as_object_mut()
        .unwrap()
        .remove("status_code");
    assert!(decode(&v).is_err());
    let batch = decode(&valid()).unwrap();
    assert_eq!(format!("{batch:?}"), "BatchV2");
    assert_eq!(format!("{:?}", batch.records()[0]), "BatchV2Record");
    assert_eq!(
        format!("{:?}", batch.records()[0].origin_witness()),
        "OriginWitness"
    );
}

#[test]
fn record_and_byte_bounds_and_unique_record_identity_are_enforced() {
    let base = valid();
    let mut body = base.clone();
    let item = base["records"][0].clone();
    let mut records = Vec::new();
    for i in 1..=500 {
        let mut row = item.clone();
        row["record"]["record_id"] = json!(format!("00000000-0000-4000-8000-{i:012x}"));
        records.push(row);
    }
    body["records"] = json!(records);
    assert_eq!(decode(&body).unwrap().record_count(), 500);
    body["records"].as_array_mut().unwrap().push(item.clone());
    assert!(decode(&body).is_err());
    body = base.clone();
    body["records"] = json!([item.clone(), item]);
    assert!(decode(&body).is_err());
    body = base.clone();
    body["records"] = json!([]);
    assert!(decode(&body).is_err());
    assert_eq!(
        BatchV2::from_wire_json(&vec![b' '; 1_048_577]).unwrap_err(),
        BatchError::Size
    );
    let mut at_limit = serde_json::to_vec(&base).unwrap();
    at_limit.resize(1_048_576, b' ');
    assert!(BatchV2::from_wire_json(&at_limit).is_ok());
    at_limit.push(b' ');
    assert_eq!(
        BatchV2::from_wire_json(&at_limit).unwrap_err(),
        BatchError::Size
    );
}

#[test]
fn v1_record_wire_is_byte_identical_inside_v2_and_v1_rejects_witness() {
    #[derive(serde::Deserialize)]
    struct RecordSlices<'a> {
        #[serde(borrow)]
        records: Vec<&'a serde_json::value::RawValue>,
    }
    let mut v1 = valid();
    v1["wire_version"] = json!(1);
    v1["records"][0] = v1["records"][0]["record"].clone();
    let legacy = Batch::from_wire_json(&serde_json::to_vec(&v1).unwrap()).unwrap();
    let legacy_wire = legacy.to_wire_json().unwrap();
    let records: RecordSlices<'_> = serde_json::from_slice(&legacy_wire).unwrap();
    let v2 = decode(&valid()).unwrap();
    assert_eq!(
        v2.records()[0].record_wire_json().unwrap(),
        records.records[0].get().as_bytes()
    );
    v1["records"][0]["origin_witness"] = json!({"kind":"unattributed"});
    assert!(Batch::from_wire_json(&serde_json::to_vec(&v1).unwrap()).is_err());
}
