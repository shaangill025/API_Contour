//! Synthetic identity fixture; no authorization or catalog processing service.
use contour_core::Batch;
use serde_json::json;
use std::io::{self, Read};

fn main() {
    if run().is_err() {
        eprintln!("operation fixture failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut bytes)?;
    let batch = Batch::from_wire_json(&bytes)?;
    let rows: Vec<_> = batch
        .operation_observations()
        .map(|observation| {
            if format!("{observation:?}") != "OperationObservation"
                || format!("{:?}", observation.key) != "OperationKey"
            {
                return Err("operation debug exposed metadata".into());
            }
            Ok(json!({
                "canonical": String::from_utf8(observation.key.canonical_bytes()?)?,
                "fingerprint": observation.key.fingerprint()?,
                "deployment_id": observation.deployment_id,
                "collector_id": observation.collector_id,
                "source_id": observation.source_id,
                "parser_profile": observation.parser_profile,
                "policy_revision": observation.policy_revision,
                "visibility": observation.visibility,
                "route_uncertain": observation.route_uncertain,
                "record_id": observation.record_id,
                "canonicalization_version": observation.canonicalization_version,
                "structure": observation.structure,
                "structure_canonical": String::from_utf8(observation.structure.canonical_bytes()?)?,
                "structure_fingerprint": observation.structure.fingerprint()?,
                "completeness": observation.completeness,
                "reasons": observation.reasons,
                "count": observation.count,
                "first_seen": observation.first_seen,
                "last_seen": observation.last_seen,
                "sample_numerator": observation.sample_numerator,
                "sample_denominator": observation.sample_denominator,
                "status_code": observation.status_code,
                "request_header_names": observation.request_header_names,
                "response_header_names": observation.response_header_names,
                "query_parameter_names": observation.query_parameter_names,
                "queued_at": observation.queued_at,
                "expires_at": observation.expires_at,
            }))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    println!("{}", serde_json::to_string(&rows)?);
    Ok(())
}
