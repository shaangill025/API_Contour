//! Synthetic comparison of checked records reconstructed from catalog evidence.
use contour_core::{Batch, compare_observed};
use serde::Deserialize;
use serde_json::{json, value::RawValue};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    left: Box<RawValue>,
    right: Box<RawValue>,
}
fn main() {
    if run().is_err() {
        eprintln!("observed comparison fixture failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(2_097_281).read_to_end(&mut bytes)?;
    if bytes.len() > 2_097_280 {
        return Err("comparison input limit".into());
    }
    let pair: Pair = serde_json::from_slice(&bytes)?;
    let left = Batch::from_wire_json(pair.left.get().as_bytes())?;
    let right = Batch::from_wire_json(pair.right.get().as_bytes())?;
    if left.record_count() != 1 || right.record_count() != 1 {
        return Err("expected one record on each side".into());
    }
    let left = left.operation_observations().next().ok_or("left missing")?;
    let right = right
        .operation_observations()
        .next()
        .ok_or("right missing")?;
    let result = match compare_observed(&left, &right) {
        Ok(comparison) => {
            if format!("{comparison:?}") != "ObservedComparison"
                || comparison
                    .differences()
                    .iter()
                    .any(|diff| format!("{diff:?}") != "ObservedDifference")
            {
                return Err("comparison debug exposed names".into());
            }
            let differences: Vec<_> = comparison.differences().iter().map(|diff| json!({
                "path":diff.path, "kind":format!("{:?}",diff.kind),
                "left_kind":diff.left_kind.map(|kind|format!("{kind:?}")),
                "right_kind":diff.right_kind.map(|kind|format!("{kind:?}")),
                "left_unknown":diff.left_unknown.map(|reason|format!("{reason:?}")),
                "right_unknown":diff.right_unknown.map(|reason|format!("{reason:?}")),
                "left_includes_null":diff.left_includes_null, "right_includes_null":diff.right_includes_null,
            })).collect();
            json!({"compatibility":format!("{:?}",comparison.compatibility()),"differences":differences})
        }
        Err(error) => json!({"error":error.to_string()}),
    };
    println!("{result}");
    Ok(())
}
