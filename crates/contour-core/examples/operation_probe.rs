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
            }))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    println!("{}", serde_json::to_string(&rows)?);
    Ok(())
}
