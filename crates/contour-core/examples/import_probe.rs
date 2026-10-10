//! Trusted fixture selectors are process arguments, never taken from document metadata.
use contour_core::{ImportSelection, MAX_IMPORT_BYTES, OperationKey, import_declared};
use std::io::{self, Read, Write};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 7 {
        std::process::exit(2);
    }
    let uuid = "00000000-0000-0000-0000-000000000001";
    let operation = OperationKey::from_components([
        uuid, uuid, uuid, uuid, "http", &args[1], &args[2], "/orders",
    ]);
    let Ok(operation) = operation else {
        std::process::exit(2);
    };
    let mut bytes = Vec::new();
    if io::stdin()
        .take((MAX_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        std::process::exit(2);
    }
    let names: Vec<&str> = args[6].split(',').filter(|v| !v.is_empty()).collect();
    let selected = ImportSelection {
        source_path: &args[3],
        media_type: &args[4],
        response_status: if args[5] == "-" { None } else { Some(&args[5]) },
    };
    match import_declared(&args[0], &bytes, operation, selected, &names).and_then(|m| {
        m.to_wire_json()
            .map_err(|_| contour_core::ImportError::Graph)
    }) {
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
