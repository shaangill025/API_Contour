//! Local synthetic-fixture encoder. Checked bytes do not authorize a batch.
use contour_core::BatchV2;
use std::io::{self, Read, Write};

const MAX_INPUT: u64 = 1_048_576;

fn encode(input: impl Read) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(());
    }
    let batch = BatchV2::from_wire_json(&bytes).map_err(|_| ())?;
    let canonical = batch.to_canonical_wire_json().map_err(|_| ())?;
    let mut hex = String::with_capacity(canonical.len() * 2);
    use std::fmt::Write as _;
    for byte in canonical {
        write!(&mut hex, "{byte:02x}").map_err(|_| ())?;
    }
    serde_json::to_vec(&serde_json::json!({
        "canonical_hex": hex,
        "digest": batch.request_digest().map_err(|_| ())?,
    }))
    .map_err(|_| ())
}

fn main() {
    let result = encode(io::stdin().lock())
        .and_then(|bytes| io::stdout().lock().write_all(&bytes).map_err(|_| ()));
    if result.is_err() {
        eprintln!("fixture encoding failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Vec<u8> {
        let fixtures: Value = serde_json::from_slice(include_bytes!(
            "../../../docs/specification/fixtures/batches-v2.json"
        ))
        .unwrap();
        serde_json::to_vec(&fixtures[0]["body"]).unwrap()
    }

    #[test]
    fn fixture_output_binds_canonical_bytes_and_golden_digest() {
        let output: Value = serde_json::from_slice(&encode(fixture().as_slice()).unwrap()).unwrap();
        let object = output.as_object().unwrap();
        assert_eq!(object.len(), 2);
        assert_eq!(
            output["digest"],
            "d3a8f1b43d3f4a1e6c7b9256112717ed94bbd0e130c9ad993c3a338b56caca1b"
        );
        let batch = BatchV2::from_wire_json(&fixture()).unwrap();
        let expected: String = batch
            .to_canonical_wire_json()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(output["canonical_hex"], expected);
    }

    #[test]
    fn rejects_duplicate_unknown_and_oversized_input() {
        let input = String::from_utf8(fixture()).unwrap();
        let duplicate = input.replacen(
            "\"wire_version\":2",
            "\"wire_version\":2,\"wire_version\":2",
            1,
        );
        let unknown = input.replacen(
            "\"wire_version\":2",
            "\"unknown\":\"SECRET\",\"wire_version\":2",
            1,
        );
        assert!(encode(duplicate.as_bytes()).is_err());
        assert!(encode(unknown.as_bytes()).is_err());
        assert!(encode(vec![b' '; MAX_INPUT as usize + 1].as_slice()).is_err());
    }
}
