use super::*;
use crate::{
    Completeness, Kind, Observation, PolicyKeys, RecordMetadata, Shape, SourceAssignment,
    VerifiedPolicy,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
const ID: &str = "00000000-0000-4000-8000-000000000001";
fn time(seconds: i64) -> OffsetDateTime {
    Timestamp::parse("2026-10-06T12:00:00Z").unwrap().instant() + Duration::seconds(seconds)
}
fn policy() -> Value {
    json!({"tenant_id":ID,"collector_id":ID,"revision":1,"issued_at":"2026-10-06T12:00:00Z","expires_at":"2026-10-06T12:15:00Z","enabled":true,"service_ids":[ID],"techniques":["runtime"],"approved_names":["GET","id"],"denied_templates":[],"inspection_bytes":65536,"depth_limit":32,"queue_bytes":268435456,"queue_ttl_seconds":86400,"durable_queue_enabled":false,"approved_route_segments":["orders"],"parser_profiles":["http_json_v1"]})
}
fn signed(value: &Value) -> VerifiedPolicy {
    let payload = serde_json::to_vec(value).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]); // Inert local test seed.
    let keys = PolicyKeys::new(&[("queue", key.verifying_key().to_bytes())]).unwrap();
    let signature = key.sign(&[b"apicontour/policy/1\n".as_slice(), &payload].concat());
    let envelope = serde_json::to_vec(&json!({"key_id":"queue","signature_profile":"ed25519-v1","payload_base64url":URL_SAFE_NO_PAD.encode(&payload),"signature_base64url":URL_SAFE_NO_PAD.encode(signature.to_bytes())})).unwrap();
    VerifiedPolicy::from_signed_json(
        &envelope,
        &keys,
        value["tenant_id"].as_str().unwrap(),
        value["collector_id"].as_str().unwrap(),
        time(0),
    )
    .unwrap()
}
fn source() -> SourceAssignment {
    SourceAssignment::new(ID, [ID; 6], "runtime", &["http_json_v1"]).unwrap()
}
fn draft(index: usize) -> RecordDraft {
    draft_shape(
        index,
        Shape::object(
            vec![("id".into(), Shape::primitive(Kind::String).unwrap())],
            None,
        )
        .unwrap(),
    )
}
fn draft_shape(index: usize, shape: Shape) -> RecordDraft {
    let id = format!("00000000-0000-4000-8000-{index:012x}");
    RecordDraft::from_observation(
        RecordMetadata {
            record_id: &id,
            source_id: ID,
            workload: [ID; 4],
            protocol: "http",
            direction: "response",
            visibility: "structure",
            operation: "GET",
            route_template: "/orders/{id}",
            route_uncertain: false,
            parser_profile: "http_json_v1",
            policy_revision: 1,
            count: 1,
            first_seen: Timestamp::from_instant(time(0)).unwrap(),
            last_seen: Timestamp::from_instant(time(0)).unwrap(),
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        },
        Observation {
            shape,
            completeness: Completeness::Complete,
            reasons: vec![],
        },
    )
    .unwrap()
}
fn queue(records: usize, bytes: usize) -> MemoryQueue {
    MemoryQueue::new([ID; 2], QueueLimits::new(records, bytes).unwrap()).unwrap()
}
fn admit(
    queue: &mut MemoryQueue,
    draft: RecordDraft,
    inputs: &AdmissionInputs<'_>,
    now: OffsetDateTime,
) -> Result<(), QueueError> {
    queue.admit_with(draft, inputs, || Ok(now))
}
#[test]
fn final_clock_expiry_purges_before_rejected_admission() {
    let current = signed(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut queue = queue(2, 100000);
    admit(&mut queue, draft(1), &inputs, time(5)).unwrap();
    let mut sample = 0;
    let result = queue.admit_with(draft(2), &inputs, || {
        sample += 1;
        Ok(if sample == 1 { time(5) } else { time(900) })
    });
    assert_eq!(result, Err(QueueError::Admission(AdmissionError::Time)));
    assert_eq!(queue.stats().records, 0);
}
#[test]
fn exact_record_and_wire_charge_capacity_drop_new() {
    let current = signed(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let charge = draft(1).retention_charge().unwrap();
    let mut full = queue(2, charge - 1);
    assert_eq!(
        admit(&mut full, draft(1), &inputs, time(5)),
        Err(QueueError::Full)
    );
    assert_eq!(full.stats().bytes, 0);
    let mut exact = queue(1, charge);
    admit(&mut exact, draft(1), &inputs, time(5)).unwrap();
    let before = exact.stats();
    assert_eq!(
        admit(&mut exact, draft(2), &inputs, time(5)),
        Err(QueueError::Full)
    );
    assert_eq!(exact.stats().bytes, before.bytes);
    assert_eq!(exact.stats().records, 1);
    assert_eq!(exact.stats().dropped, 1);
    let entry = exact.entries.front().unwrap();
    let encoded = crate::Batch::assemble(
        ID,
        [ID; 2],
        Timestamp::from_instant(time(5)).unwrap(),
        vec![
            draft(3)
                .declare_queue_times(
                    Timestamp::from_instant(time(5)).unwrap(),
                    Timestamp::from_instant(time(86405)).unwrap(),
                )
                .unwrap(),
        ],
    )
    .unwrap()
    .to_wire_json()
    .unwrap();
    assert!(encoded.len() <= entry.charge);
}
#[test]
fn successful_reservation_owns_timestamps_and_expiry_boundary() {
    let mut value = policy();
    value["queue_ttl_seconds"] = json!(10);
    let current = signed(&value);
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut queue = queue(2, 100000);
    let mut sample = 0;
    queue
        .admit_with(draft(1), &inputs, || {
            sample += 1;
            Ok(time(sample))
        })
        .unwrap();
    let entry = queue.entries.front().unwrap();
    assert_eq!(entry.record.queued_at().instant(), time(2));
    assert_eq!(entry.record.expires_at().instant(), time(12));
    queue.reconcile_at(&inputs, time(11)).unwrap();
    assert_eq!(queue.stats().records, 1);
    queue.reconcile_at(&inputs, time(12)).unwrap();
    assert_eq!(queue.stats().records, 0);
    assert_eq!(queue.stats().expired, 1);
}
#[test]
fn narrowing_dimensions_and_quota_shrink_purge_without_rewriting() {
    let old = signed(&policy());
    let sources = [source()];
    let initial = AdmissionInputs::new([ID; 2], &old, &[&old], &sources).unwrap();
    for (field, value) in [
        ("approved_names", json!(["GET"])),
        ("service_ids", json!([])),
        ("techniques", json!([])),
        ("parser_profiles", json!([])),
        ("approved_route_segments", json!([])),
        ("denied_templates", json!(["/orders/{segment}"])),
        ("queue_ttl_seconds", json!(1)),
        ("queue_bytes", json!(1)),
        ("depth_limit", json!(1)),
    ] {
        let mut queue = queue(2, 100000);
        admit(&mut queue, draft(1), &initial, time(5)).unwrap();
        let mut value2 = policy();
        value2["revision"] = json!(2);
        value2[field] = value;
        let new = signed(&value2);
        let inputs = AdmissionInputs::new([ID; 2], &new, &[&old], &sources).unwrap();
        queue.reconcile_at(&inputs, time(6)).unwrap();
        assert_eq!(queue.stats().records, 0, "{field}");
        assert_eq!(queue.stats().purged, 1);
    }
}
#[test]
fn source_removal_historical_expiry_and_revision_guard() {
    let mut value = policy();
    value["expires_at"] = json!("2026-10-06T12:00:10Z");
    let old = signed(&value);
    let sources = [source()];
    let initial = AdmissionInputs::new([ID; 2], &old, &[&old], &sources).unwrap();
    let mut queue = queue(3, 100000);
    admit(&mut queue, draft(1), &initial, time(5)).unwrap();
    let mut new_value = policy();
    new_value["revision"] = json!(2);
    let new = signed(&new_value);
    let current = AdmissionInputs::new([ID; 2], &new, &[&old], &sources).unwrap();
    queue.reconcile_at(&current, time(11)).unwrap();
    assert_eq!(queue.stats().records, 1);
    assert_eq!(
        queue.reconcile_at(&initial, time(6)),
        Err(QueueError::Revision)
    );
    assert_eq!(queue.stats().records, 0);
    let mut conflicting = new_value.clone();
    conflicting["queue_bytes"] = json!(999);
    let conflict = signed(&conflicting);
    let inputs = AdmissionInputs::new([ID; 2], &conflict, &[&old], &sources).unwrap();
    assert_eq!(
        queue.reconcile_at(&inputs, time(11)),
        Err(QueueError::Revision)
    );
    let empty = AdmissionInputs::new([ID; 2], &new, &[&old], &[]).unwrap();
    // New queue proves source removal independently of its high-water guard.
    let mut another =
        super::MemoryQueue::new([ID; 2], QueueLimits::new(2, 100000).unwrap()).unwrap();
    admit(&mut another, draft(1), &initial, time(5)).unwrap();
    another.reconcile_at(&empty, time(11)).unwrap();
    assert_eq!(another.stats().records, 0);
}
#[test]
fn disabled_update_keeps_highwater_and_revoke_is_permanent() {
    let old = signed(&policy());
    let sources = [source()];
    let initial = AdmissionInputs::new([ID; 2], &old, &[&old], &sources).unwrap();
    let mut queue = queue(2, 100000);
    admit(&mut queue, draft(1), &initial, time(5)).unwrap();
    let mut value = policy();
    value["revision"] = json!(2);
    value["enabled"] = json!(false);
    let disabled = signed(&value);
    let update = AdmissionInputs::new([ID; 2], &disabled, &[&old], &sources).unwrap();
    assert!(queue.reconcile_at(&update, time(6)).is_err());
    assert_eq!(
        queue.reconcile_at(&initial, time(6)),
        Err(QueueError::Revision)
    );
    queue.revoke();
    assert_eq!(
        queue.reconcile_at(&initial, time(6)),
        Err(QueueError::Revoked)
    );
    assert_eq!(
        admit(&mut queue, draft(1), &initial, time(6)),
        Err(QueueError::Revoked)
    );
    assert_eq!(queue.stats().bytes, 0);
    assert_eq!(format!("{queue:?}"), "MemoryQueue");
}
#[test]
fn limits_duplicate_clock_failure_and_saturating_health() {
    for (records, bytes) in [(0, 1), (501, 1), (1, 0), (1, 268435457)] {
        assert!(QueueLimits::new(records, bytes).is_err());
    }
    let current = signed(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut queue = queue(2, 100000);
    admit(&mut queue, draft(1), &inputs, time(5)).unwrap();
    assert_eq!(
        admit(&mut queue, draft(1), &inputs, time(5)),
        Err(QueueError::Record)
    );
    assert_eq!(queue.stats().records, 1);
    queue.stats.rejected = u64::MAX;
    assert_eq!(
        queue.admit_with(draft(2), &inputs, || Err(QueueError::Clock)),
        Err(QueueError::Clock)
    );
    assert_eq!(queue.stats().rejected, u64::MAX);
    assert_eq!(queue.stats().records, 0);
    assert!(Timestamp::from_instant(wall_clock().unwrap()).is_ok());
}

#[test]
fn reconciliation_clock_failure_counts_rejection_and_preserves_guard() {
    let current = signed(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut queue = queue(2, 100000);
    admit(&mut queue, draft(1), &inputs, time(5)).unwrap();
    let guard = queue.high_water;
    assert_eq!(
        queue.clock_result(Err(QueueError::Clock)),
        Err(QueueError::Clock)
    );
    assert_eq!(queue.stats().records, 0);
    assert_eq!(queue.stats().bytes, 0);
    assert_eq!(queue.stats().purged, 1);
    assert_eq!(queue.stats().rejected, 1);
    assert_eq!(queue.high_water, guard);
    queue.stats.rejected = u64::MAX;
    assert_eq!(
        queue.clock_result(Err(QueueError::Clock)),
        Err(QueueError::Clock)
    );
    assert_eq!(queue.stats().rejected, u64::MAX);
}

#[test]
fn distinct_snapshot_identity_and_nested_name_reject_without_retention() {
    let current = signed(&policy());
    let sources = [source()];
    let inputs = AdmissionInputs::new([ID; 2], &current, &[&current], &sources).unwrap();
    let mut queue = queue(2, 100000);
    let nested = draft_shape(
        1,
        Shape::object(
            vec![(
                "id".into(),
                Shape::array(
                    Shape::object(
                        vec![(
                            "SYNTHETIC_SECRET".into(),
                            Shape::primitive(Kind::String).unwrap(),
                        )],
                        None,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )],
            None,
        )
        .unwrap(),
    );
    assert_eq!(
        admit(&mut queue, nested, &inputs, time(5)),
        Err(QueueError::Admission(AdmissionError::Scope))
    );
    assert_eq!(queue.stats().records, 0);
    assert_eq!(queue.stats().bytes, 0);
    admit(&mut queue, draft(2), &inputs, time(5)).unwrap();
    let other = "00000000-0000-4000-8000-000000000099";
    let mut value = policy();
    value["tenant_id"] = json!(other);
    let foreign = signed(&value);
    let source = SourceAssignment::new(
        ID,
        [other, ID, ID, ID, ID, ID],
        "runtime",
        &["http_json_v1"],
    )
    .unwrap();
    let sources = [source];
    let foreign_inputs =
        AdmissionInputs::new([other, ID], &foreign, &[&foreign], &sources).unwrap();
    assert_eq!(
        queue.reconcile_at(&foreign_inputs, time(6)),
        Err(QueueError::Identity)
    );
    assert_eq!(queue.stats().records, 0);
    assert_eq!(queue.stats().bytes, 0);
    assert_eq!(queue.stats().purged, 1);
}
