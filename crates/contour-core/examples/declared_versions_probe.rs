//! Bounded executable fixture, independently reloads both graph wire documents.
use contour_core::{DeclaredContract, MAX_DECLARED_BYTES, compare_declared_versions};
use std::io::{self, Read};
fn main() {
    let result = run();
    match result {
        Ok(value) => println!("{value}"),
        Err(code) => {
            eprintln!("{code}");
            std::process::exit(1);
        }
    }
}
fn run() -> Result<serde_json::Value, String> {
    let mut input = Vec::new();
    io::stdin()
        .take((2 * MAX_DECLARED_BYTES + 4097) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "Input".to_string())?;
    if input.len() > 2 * MAX_DECLARED_BYTES + 4096 {
        return Err("Input".into());
    }
    let pair: [Box<serde_json::value::RawValue>; 2] =
        serde_json::from_slice(&input).map_err(|_| "Input".to_string())?;
    let decode = |raw: &str| -> Result<DeclaredContract, String> {
        let first = DeclaredContract::from_wire_json(raw.as_bytes()).map_err(|e| e.to_string())?;
        let bytes = first.to_wire_json().map_err(|e| e.to_string())?;
        let second = DeclaredContract::from_wire_json(&bytes).map_err(|e| e.to_string())?;
        if first != second {
            return Err("Reload".into());
        }
        Ok(second)
    };
    let result = compare_declared_versions(&decode(pair[0].get())?, &decode(pair[1].get())?)
        .map_err(|e| e.to_string())?;
    // Large valid comparisons can exceed the storage codec's separate byte cap.
    match result.to_wire_json() {
        Ok(wire) => {
            let reloaded = contour_core::DeclaredVersionComparison::from_wire_json(&wire)
                .map_err(|e| e.to_string())?;
            if result != reloaded || reloaded.to_wire_json().map_err(|e| e.to_string())? != wire {
                return Err("Reload".into());
            }
        }
        Err(contour_core::DeclaredComparisonCodecError::Size) => (),
        Err(error) => return Err(error.to_string()),
    }
    Ok(
        serde_json::json!({"compatibility":format!("{:?}",result.compatibility()),"differences":result.differences().iter().map(|d|serde_json::json!({
        "path":d.path,"kind":format!("{:?}",d.kind),
        "baseline_kind":d.baseline_kind.map(|k|format!("{k:?}")),
        "candidate_kind":d.candidate_kind.map(|k|format!("{k:?}")),
            "baseline_required":d.baseline_required,"candidate_required":d.candidate_required,
            "baseline_includes_null":d.baseline_includes_null,"candidate_includes_null":d.candidate_includes_null,
            "baseline_additional":d.baseline_additional.map(|p|format!("{p:?}")),
            "candidate_additional":d.candidate_additional.map(|p|format!("{p:?}")),
    })).collect::<Vec<_>>()}),
    )
}
