# APIContour

The first native Rust core slice constructs normalized structural nodes and emits
canonical UTF-8 JSON array trees. It stores field names and kinds, never observed
values. Callers must approve names through policy before constructing objects;
structural validation does not grant policy authorization.

Requires Rust 1.88 or later. No external dependencies.

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

Hashing, parsing, policy enforcement, collection, persistence, WASM and FFI remain
unimplemented. This slice is not a complete R1 product.
