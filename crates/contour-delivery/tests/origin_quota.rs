use contour_core::{
    AdmissionInputs, Completeness, Kind, MemoryQueue, Observation, OriginWitness, PolicyKeys,
    QueueLimits, RecordDraft, RecordMetadata, Shape, SourceAssignment, Timestamp, VerifiedPolicy,
};
use contour_delivery::{DeliveryError, RetryController, RetryDirective, RetryError};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use time::OffsetDateTime;

const ID: &str = "00000000-0000-4000-8000-000000000001";

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        result.push(TABLE[((bits >> 18) & 63) as usize] as char);
        result.push(TABLE[((bits >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((bits >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(TABLE[(bits & 63) as usize] as char);
        }
    }
    result
}
fn stamp(t: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

#[test]
fn origin_quota_is_terminal_and_preserves_frozen_bytes() {
    let now = OffsetDateTime::now_utc();
    let signing = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let keys =
        PolicyKeys::new(&[("test", signing.public_key().as_ref().try_into().unwrap())]).unwrap();
    let payload = serde_json::to_vec(&json!({"tenant_id":ID,"collector_id":ID,"revision":1,"issued_at":stamp(now-time::Duration::minutes(1)),"expires_at":stamp(now+time::Duration::minutes(2)),"enabled":true,"service_ids":[ID],"techniques":["runtime"],"approved_names":["GET","id"],"denied_templates":[],"inspection_bytes":65536,"depth_limit":32,"queue_bytes":100000,"queue_ttl_seconds":60,"durable_queue_enabled":false,"approved_route_segments":["orders"],"parser_profiles":["http_json_v1"]})).unwrap();
    let signature = signing.sign(&[b"apicontour/policy/1\n".as_slice(), &payload].concat());
    let envelope = serde_json::to_vec(&json!({"payload_base64url":base64url(&payload),"signature_base64url":base64url(signature.as_ref()),"key_id":"test","signature_profile":"ed25519-v1"})).unwrap();
    let policy = VerifiedPolicy::from_signed_json(&envelope, &keys, ID, ID, now).unwrap();
    let sources = [SourceAssignment::new(ID, [ID; 6], "runtime", &["http_json_v1"]).unwrap()];
    let policies = [&policy];
    let inputs = AdmissionInputs::new([ID; 2], &policy, &policies, &sources).unwrap();
    let seen = Timestamp::parse(&stamp(now)).unwrap();
    let record = RecordDraft::from_observation(
        RecordMetadata {
            record_id: ID,
            source_id: ID,
            workload: [ID; 4],
            protocol: "http",
            direction: "request",
            visibility: "structure",
            operation: "GET",
            route_template: "/orders",
            route_uncertain: false,
            parser_profile: "http_json_v1",
            policy_revision: 1,
            count: 1,
            first_seen: seen.clone(),
            last_seen: seen,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: None,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        },
        Observation {
            shape: Shape::object(
                vec![("id".into(), Shape::primitive(Kind::String).unwrap())],
                None,
            )
            .unwrap(),
            completeness: Completeness::Complete,
            reasons: vec![],
        },
    )
    .unwrap();
    let mut queue = MemoryQueue::new_v2([ID; 2], QueueLimits::new(2, 100000).unwrap()).unwrap();
    queue
        .admit_v2(record, OriginWitness::Unattributed, &inputs)
        .unwrap();
    let frozen = queue.freeze(ID, 1, &inputs).unwrap().unwrap();
    let bytes = frozen.wire().to_vec();
    let binding = frozen.binding();
    let charge = queue.stats().bytes;
    let mut attempt = queue.reserve_delivery(&inputs).unwrap().unwrap();
    let mut retry = RetryController::for_attempt(&mut attempt);
    assert_eq!(
        retry
            .on_failure(
                binding,
                DeliveryError::Rejected {
                    status: 423,
                    retry_after: None
                }
            )
            .unwrap(),
        RetryDirective::StopRejected(423)
    );
    assert_eq!(
        retry.on_failure(binding, DeliveryError::Transport),
        Err(RetryError::Stopped)
    );
    drop(attempt);
    assert_eq!(queue.stats().bytes, charge);
    let mut again = queue.reserve_delivery(&inputs).unwrap().unwrap();
    assert_eq!(again.view().binding(), binding);
    assert_eq!(again.view().wire(), bytes);
}
