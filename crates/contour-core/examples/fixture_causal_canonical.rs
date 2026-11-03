//! Print canonical bytes and domain-separated digest for the normative fixture.
use contour_core::CausalEventBatch;
fn main() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/causal-events.json"
    ))
    .unwrap();
    let input = serde_json::to_vec(&fixtures[0]["body"]).unwrap();
    let batch = CausalEventBatch::from_wire_json(&input).unwrap();
    println!(
        "{}",
        String::from_utf8(batch.canonical_bytes().unwrap()).unwrap()
    );
    for byte in batch.digest_bytes().unwrap() {
        print!("{byte:02x}");
    }
    println!();
}
