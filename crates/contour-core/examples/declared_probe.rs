//! Bounded executable codec fixture; never imports source documents.
use contour_core::{DeclaredContract, MAX_DECLARED_BYTES};
use std::io::{self, Read, Write};
fn main() {
    let mut bytes = Vec::new();
    if io::stdin()
        .take((MAX_DECLARED_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        std::process::exit(2);
    }
    let result = DeclaredContract::from_wire_json(&bytes).and_then(|value| {
        let wire = value.to_wire_json()?;
        let reloaded = DeclaredContract::from_wire_json(&wire)?;
        if reloaded != value || reloaded.to_wire_json()? != wire {
            return Err(contour_core::DeclaredError::Invalid);
        }
        Ok(wire)
    });
    match result {
        Ok(wire) => {
            if io::stdout().write_all(&wire).is_err() {
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
