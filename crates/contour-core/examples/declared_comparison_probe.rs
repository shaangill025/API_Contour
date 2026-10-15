//! Checked declared reload and checked persisted-observation reconstruction.
use contour_core::{Batch, DeclaredContract, compare_declared_observation};
use serde::Deserialize;
use serde_json::{json, value::RawValue};
use std::io::{self, Read};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    declared: Box<RawValue>,
    observed: Box<RawValue>,
}
fn main() {
    if run().is_err() {
        eprintln!("declared observation fixture failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(2_097_281).read_to_end(&mut bytes)?;
    if bytes.len() > 2_097_280 {
        return Err("fixture input bound".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    let declared = DeclaredContract::from_wire_json(input.declared.get().as_bytes())?;
    let wire = declared.to_wire_json()?;
    let declared_again = DeclaredContract::from_wire_json(&wire)?;
    if declared != declared_again {
        return Err("declared reload changed".into());
    }
    let batch = Batch::from_wire_json(input.observed.get().as_bytes())?;
    if batch.record_count() != 1 {
        return Err("fixture record count".into());
    }
    let observation = batch
        .operation_observations()
        .next()
        .ok_or("missing record")?;
    let result = match compare_declared_observation(&declared_again, &observation) {
        Ok(result) => {
            if format!("{result:?}") != "DeclaredObservationComparison"
                || result
                    .differences()
                    .iter()
                    .any(|d| format!("{d:?}") != "DeclaredObservationDifference")
            {
                return Err("debug exposed evidence".into());
            }
            let differences: Vec<_> = result
                .differences()
                .iter()
                .map(|d| {
                    json!({
                        "path": d.path, "kind": format!("{:?}", d.kind),
                        "declared_kind": d.declared_kind.map(|k| format!("{k:?}")),
                        "observed_kind": d.observed_kind.map(|k| format!("{k:?}")),
                        "declared_unknown": d.declared_unknown.map(|k| format!("{k:?}")),
                        "observed_unknown": d.observed_unknown.map(|k| format!("{k:?}")),
                    })
                })
                .collect();
            json!({"compatibility":format!("{:?}",result.compatibility()),"differences":differences})
        }
        Err(error) => json!({"error":error.to_string()}),
    };
    println!("{result}");
    Ok(())
}
