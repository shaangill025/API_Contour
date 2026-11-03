use contour_core::{Batch, BatchV2, CausalEventBatch, CausalEventKind, LossReason};
use sha2::{Digest, Sha256};

const VALID: &str = r#"{"wire_version":1,"batch_id":"123e4567-e89b-12d3-a456-426614174000","tenant_id":"123e4567-e89b-12d3-a456-426614174001","runtime_id":"123e4567-e89b-12d3-a456-426614174002","session_epoch":1,"first_seq":1,"last_seq":3,"events":[{"kind":"root","event_id":"11111111111111111111111111111111","seq":1,"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"kind":"loss","event_id":"22222222222222222222222222222222","seq":3,"first_missing_seq":2,"last_missing_seq":2,"reason":"overflow"}]}"#;
#[test]
fn canonical_and_domains() {
    let b = CausalEventBatch::from_wire_json(VALID.as_bytes()).unwrap();
    let bytes = b.canonical_bytes().unwrap();
    let parsed = CausalEventBatch::from_wire_json(&bytes).unwrap();
    assert_eq!(parsed.canonical_bytes().unwrap(), bytes);
    let mut h = Sha256::new();
    h.update(b"apicontour/caausal-events/1\n");
    h.update(&bytes);
    assert_ne!(
        b.digest_bytes().unwrap().as_slice(),
        h.finalize().as_slice()
    );
    let mut h = Sha256::new();
    h.update(b"apicontour/causal-events/1\n");
    h.update(&bytes);
    assert_eq!(
        b.digest_bytes().unwrap().as_slice(),
        h.finalize().as_slice()
    );
    let event = &b.events()[0];
    let mut h = Sha256::new();
    h.update(b"apicontour/causal-event/1\n");
    h.update(event.canonical_bytes().unwrap());
    assert_eq!(
        event.digest_bytes().unwrap().as_slice(),
        h.finalize().as_slice()
    );
    assert!(Batch::from_wire_json(&bytes).is_err());
    assert!(BatchV2::from_wire_json(&bytes).is_err());
}
#[test]
fn rejects_invalid() {
    for bad in [
        VALID.replace("\"session_epoch\":1", "\"session_epoch\":1.0"),
        VALID.replace("\"session_epoch\":1", "\"session_epoch\":0"),
        VALID.replace(
            "\"session_epoch\":1",
            "\"session_epoch\":18446744073709551616",
        ),
        VALID.replace("\"session_epoch\":1", "\"session_epoch\":true"),
        VALID.replace("\"session_epoch\":1", "\"session_epoch\":\"1\""),
        VALID.replace(
            "\"session_epoch\":1",
            "\"session_epoch\":1,\"session_epoch\":1",
        ),
        VALID.replace("\"kind\":\"root\"", "\"kind\":\"alien\""),
        VALID.replace("\"kind\":\"root\"", "\"extra\":1,\"kind\":\"root\""),
        VALID.replace("\"first_missing_seq\":2", "\"first_missing_seq\":1"),
        VALID.replace("\"last_missing_seq\":2", "\"last_missing_seq\":3"),
        VALID.replace(
            "22222222222222222222222222222222",
            "11111111111111111111111111111111",
        ),
        VALID.replace("\"seq\":3", "\"seq\":1"),
        VALID.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        VALID.replace("\"events\":[", "\"events\":[],\"other\":["),
    ] {
        assert!(
            CausalEventBatch::from_wire_json(bad.as_bytes()).is_err(),
            "{bad}"
        );
    }
    assert!(CausalEventBatch::from_wire_json(&vec![b' '; 1_048_577]).is_err());
    let value: serde_json::Value = serde_json::from_str(VALID).unwrap();
    let mut many = value.clone();
    many["events"] = serde_json::Value::Array(vec![value["events"][0].clone(); 501]);
    assert!(CausalEventBatch::from_wire_json(&serde_json::to_vec(&many).unwrap()).is_err());
}

#[test]
fn normative_golden() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/causal-events.json"
    ))
    .unwrap();
    for fixture in fixtures
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["expected"] == "accept")
    {
        let input = serde_json::to_vec(&fixture["body"]).unwrap();
        let batch = CausalEventBatch::from_wire_json(&input).unwrap();
        let encoded = batch.canonical_bytes().unwrap();
        assert_eq!(encoded, fixture["canonical"].as_str().unwrap().as_bytes());
        assert_eq!(encoded.len(), fixture["bytes"].as_u64().unwrap() as usize);
        assert_eq!(
            format!(
                "{:x}",
                sha2::digest::Output::<Sha256>::from(batch.digest_bytes().unwrap())
            ),
            fixture["sha256"].as_str().unwrap()
        );
        for (event, golden) in batch
            .events()
            .iter()
            .zip(fixture["events"].as_array().unwrap())
        {
            let bytes = event.canonical_bytes().unwrap();
            assert_eq!(bytes, golden["canonical"].as_str().unwrap().as_bytes());
            assert_eq!(bytes.len(), golden["bytes"].as_u64().unwrap() as usize);
            assert_eq!(
                format!(
                    "{:x}",
                    sha2::digest::Output::<Sha256>::from(event.digest_bytes().unwrap())
                ),
                golden["sha256"].as_str().unwrap()
            );
        }
    }
}

fn causal_fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/causal-events.json"
    ))
    .unwrap()
}
fn all_variants() -> serde_json::Value {
    causal_fixtures()[1]["body"].clone()
}
fn decode_value(v: &serde_json::Value) -> Result<CausalEventBatch, contour_core::BatchError> {
    CausalEventBatch::from_wire_json(&serde_json::to_vec(v).unwrap())
}
#[test]
fn fixture_outcomes_and_checked_views() {
    for f in causal_fixtures().as_array().unwrap() {
        assert_eq!(
            decode_value(&f["body"]).is_ok(),
            f["expected"] == "accept",
            "{}",
            f["id"]
        );
    }
    let b = decode_value(&all_variants()).unwrap();
    assert_eq!(
        b.events()[0].kind(),
        CausalEventKind::Root {
            root: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    );
    assert_eq!(
        b.events()[1].kind(),
        CausalEventKind::Delivery {
            root: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            activity: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            parent: "cccccccccccccccccccccccccccccccc"
        }
    );
    assert_eq!(
        b.events()[2].kind(),
        CausalEventKind::Attempt {
            root: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            activity: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            attempt: "dddddddddddddddddddddddddddddddd",
            marker_digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }
    );
    assert_eq!(
        b.events()[3].kind(),
        CausalEventKind::Loss {
            first_missing_seq: 4,
            last_missing_seq: 4,
            reason: LossReason::DispatchMissing
        }
    );
}
fn reverse_objects(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .rev()
                .map(|(k, v)| format!(
                    "{}:{}",
                    serde_json::to_string(k).unwrap(),
                    reverse_objects(v)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Array(a) => format!(
            "[{}]",
            a.iter().map(reverse_objects).collect::<Vec<_>>().join(",")
        ),
        _ => v.to_string(),
    }
}
#[test]
fn key_order_equivalence_and_changed_semantics() {
    let value = all_variants();
    let a = decode_value(&value).unwrap();
    let b = CausalEventBatch::from_wire_json(reverse_objects(&value).as_bytes()).unwrap();
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
    assert_eq!(a.digest_bytes().unwrap(), b.digest_bytes().unwrap());
    for (x, y) in a.events().iter().zip(b.events()) {
        assert_eq!(x.canonical_bytes().unwrap(), y.canonical_bytes().unwrap());
        assert_eq!(x.digest_bytes().unwrap(), y.digest_bytes().unwrap());
    }
    let mut changed = value;
    changed["events"][2]["marker_digest"] = "f".repeat(64).into();
    let c = decode_value(&changed).unwrap();
    assert_ne!(a.digest_bytes().unwrap(), c.digest_bytes().unwrap());
    assert_ne!(
        a.events()[2].digest_bytes().unwrap(),
        c.events()[2].digest_bytes().unwrap()
    );
}
#[test]
fn legacy_cross_decode_and_frozen_bytes() {
    let v1: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/batches.json"
    ))
    .unwrap();
    let v2: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/batches-v2.json"
    ))
    .unwrap();
    let one = serde_json::to_vec(&v1[0]["body"]).unwrap();
    let two = serde_json::to_vec(&v2[0]["body"]).unwrap();
    assert!(CausalEventBatch::from_wire_json(&one).is_err());
    assert!(CausalEventBatch::from_wire_json(&two).is_err());
    let one = Batch::from_wire_json(&one).unwrap();
    let two = BatchV2::from_wire_json(&two).unwrap();
    assert_eq!(
        one.request_digest().unwrap(),
        "b255b40f1473896fb764a41f795be943d87da2547fed5ea8bd7d6877b5a4fa0b"
    );
    assert_eq!(
        two.request_digest().unwrap(),
        "d3a8f1b43d3f4a1e6c7b9256112717ed94bbd0e130c9ad993c3a338b56caca1b"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(one.to_wire_json().unwrap())),
        "c284b5085ccd8f099c902ed4cb76ca82422bb7e93e35ddda8a94e34565f6ea14"
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(two.to_canonical_wire_json().unwrap())
        ),
        "a3cefc093fa936bed286c6f34d5ca8495e439974e66270d692babe1ae65eccd4"
    );
}

#[test]
fn strict_tokens_duplicates_limits_and_closed_fields() {
    let text = serde_json::to_string(&all_variants()).unwrap();
    for (needle, replacements) in [
        (
            "\"wire_version\":1",
            vec![
                "\"wire_version\":1.0",
                "\"wire_version\":1e0",
                "\"wire_version\":-1",
                "\"wire_version\":true",
                "\"wire_version\":\"1\"",
            ],
        ),
        (
            "\"session_epoch\":1",
            vec![
                "\"session_epoch\":1.0",
                "\"session_epoch\":1e0",
                "\"session_epoch\":null",
                "\"session_epoch\":18446744073709551616",
            ],
        ),
        (
            "\"seq\":2",
            vec![
                "\"seq\":2.0",
                "\"seq\":2e0",
                "\"seq\":false",
                "\"seq\":\"2\"",
                "\"seq\":18446744073709551616",
                "\"seq\":2,\"seq\":2",
            ],
        ),
        (
            "\"first_missing_seq\":4",
            vec![
                "\"first_missing_seq\":4.0",
                "\"first_missing_seq\":4e0",
                "\"first_missing_seq\":\"4\"",
            ],
        ),
        (
            "\"kind\":\"delivery\"",
            vec![
                "\"kind\":\"delivery\",\"kind\":\"delivery\"",
                "\"kind\":\"delivery\",\"url\":\"x\"",
                "\"kind\":\"delivery\",\"verified\":true",
            ],
        ),
    ] {
        assert!(text.contains(needle));
        for replacement in replacements {
            assert!(
                CausalEventBatch::from_wire_json(text.replacen(needle, replacement, 1).as_bytes())
                    .is_err(),
                "accepted {replacement}"
            );
        }
    }
    for field in ["root", "activity", "parent", "attempt", "marker_digest"] {
        let mut value = all_variants();
        let index = if field == "parent" {
            1
        } else if field == "root" {
            0
        } else {
            2
        };
        value["events"][index][field] = "x".into();
        assert!(decode_value(&value).is_err(), "accepted {field}");
    }
    for reason in [
        "overflow",
        "expired",
        "canceled",
        "guard_invalidated",
        "dispatch_missing",
        "restart",
        "unsupported",
    ] {
        let mut value = all_variants();
        value["events"][3]["reason"] = reason.into();
        assert!(decode_value(&value).is_ok(), "rejected {reason}");
    }
    let mut value = all_variants();
    let event = value["events"][0].clone();
    let mut events = Vec::new();
    for i in 1..=500 {
        let mut e = event.clone();
        e["seq"] = i.into();
        e["event_id"] = format!("{i:032x}").into();
        e["root"] = format!("{i:032x}").into();
        events.push(e);
    }
    value["events"] = events.into();
    value["last_seq"] = 500.into();
    assert_eq!(decode_value(&value).unwrap().events().len(), 500);
    let mut next = value["events"][0].clone();
    next["seq"] = 501.into();
    next["event_id"] = format!("{:032x}", 501).into();
    next["root"] = format!("{:032x}", 501).into();
    value["events"].as_array_mut().unwrap().push(next);
    value["last_seq"] = 501.into();
    assert!(decode_value(&value).is_err());
    let mut padded = serde_json::to_vec(&all_variants()).unwrap();
    padded.resize(1_048_576, b' ');
    assert!(CausalEventBatch::from_wire_json(&padded).is_ok());
    padded.push(b' ');
    assert!(CausalEventBatch::from_wire_json(&padded).is_err());
}

#[test]
fn positive_u64_boundaries_remain_exact() {
    let fixtures = causal_fixtures();
    let fixture = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "u64_boundaries")
        .unwrap();
    let batch = decode_value(&fixture["body"]).unwrap();
    assert_eq!(batch.session_epoch(), u64::MAX);
    assert_eq!(batch.first_seq(), 9_007_199_254_740_993);
    assert_eq!(batch.last_seq(), u64::MAX);
    assert_eq!(
        batch.events()[1].kind(),
        CausalEventKind::Loss {
            first_missing_seq: 9_007_199_254_740_994,
            last_missing_seq: u64::MAX - 1,
            reason: LossReason::Overflow,
        }
    );
}
