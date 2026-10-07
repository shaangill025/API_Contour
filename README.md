# APIContour

The native Rust core constructs normalized structural nodes, emits canonical
UTF-8 JSON array trees, decodes and encodes structure-only wire JSON, and computes
versioned domain-separated SHA-256 fingerprints. It stores field names and kinds, never observed
values. Callers must approve names through policy before constructing objects;
structural validation does not grant policy authorization.

Requires Rust 1.88 or later. Dependencies are pinned serde, serde_json and sha2.

```sh
cargo test --workspace --locked --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo build --workspace --locked --offline
```

Limits: 1–64 Unicode scalars per name, 256 fields per object, 32 node levels
(root counts as one), 64 direct union input alternatives and 64 distinct
flattened union alternatives, and 65,536 canonical bytes. Empty unions are
rejected; a single normalized alternative collapses.
Empty arrays use unknown/empty items. Union sort keys share a 65,536-byte bound.
Wire input and output each have a separate 65,536-byte limit. Wire unions require
2–64 unique alternatives and reject directly nested unions. Duplicate JSON keys,
unknown properties, observed values, malformed input and trailing content are
rejected with static errors. Names still require caller policy approval.

Local JSON extraction uses borrowed raw tokens and explicit static-name/child
policies. Explicit denied paths take precedence over dynamic inspection.
Default policy exports no names. Dynamic keys become additional-value
structure only. Numbers are classified exactly, without floating-point conversion.
The profile bounds inspected bodies to 64 KiB, all inspected object keys to 256,
array items to 64, numeric tokens to 256 bytes, and node depth to 32.

Skipped policy subtrees yield partial/permission evidence; they have not been
duplicate-validated. Detected malformed input or decoded duplicate keys yields
unavailable/malformed. Any resource limit conservatively replaces the whole
result with unknown/limit and partial status, including canonical or wire output
overflow. A 2 ms cooperative deadline is
checked around bounded serde scans; it is not a hard interruption guarantee.
Raw tokens and decoded values exist only transiently and are never returned.

Capture authorization, policy signature/lease enforcement, collection,
persistence, WASM and FFI remain unimplemented. This is not a complete R1 product.
