//! Bounded synthetic comparison-codec fixture; errors never contain source values.
use contour_core::{
    DeclaredContract, DeclaredVersionComparison, MAX_DECLARED_COMPARISON_BYTES,
    compare_declared_versions,
};
use std::io::{self, Read};
fn main() {
    match run() {
        Ok(bytes) => {
            use std::io::Write;
            io::stdout().write_all(&bytes).expect("fixture stdout");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
fn run() -> Result<Vec<u8>, String> {
    let compare = match std::env::args().nth(1).as_deref() {
        Some("compare") => true,
        Some("decode") => false,
        _ => return Err("Input".into()),
    };
    let max = if compare {
        2 * MAX_DECLARED_COMPARISON_BYTES + 4096
    } else {
        MAX_DECLARED_COMPARISON_BYTES
    };
    let mut bytes = Vec::new();
    io::stdin()
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Input")?;
    if bytes.len() > max {
        return Err("Size".into());
    }
    let value = if compare {
        let pair: [Box<serde_json::value::RawValue>; 2] =
            serde_json::from_slice(&bytes).map_err(|_| "Input")?;
        let a = DeclaredContract::from_wire_json(pair[0].get().as_bytes())
            .map_err(|e| e.to_string())?;
        let b = DeclaredContract::from_wire_json(pair[1].get().as_bytes())
            .map_err(|e| e.to_string())?;
        compare_declared_versions(&a, &b).map_err(|e| e.to_string())?
    } else {
        DeclaredVersionComparison::from_wire_json(&bytes).map_err(|e| e.to_string())?
    };
    let encoded = value.to_wire_json().map_err(|e| e.to_string())?;
    let reloaded =
        DeclaredVersionComparison::from_wire_json(&encoded).map_err(|e| e.to_string())?;
    if reloaded != value || reloaded.to_wire_json().map_err(|e| e.to_string())? != encoded {
        return Err("Reload".into());
    }
    Ok(encoded)
}
