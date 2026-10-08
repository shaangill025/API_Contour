# WebAssembly structural interface

Build with `cargo +1.88.0 build -p contour-wasm --target wasm32-unknown-unknown --locked --offline`. Load `contour_wasm.wasm` with the host WebAssembly runtime. No imports, filesystem, network, clock or external JavaScript package are needed.

Use an unshared, single-threaded instance. Read the input offset and capacity from `contour_wasm_input_v1` and `contour_wasm_capacity_v1`. Write at most 65,536 bytes of structure-only JSON there, then call `contour_wasm_process_v1(length)`. Status 0 means success; status 2 rejects input. Read the canonical/fingerprint offsets and lengths only after success. The fingerprint is 64 lowercase hexadecimal bytes. Lengths exclude NUL terminators.

Each call clears the input and previous outputs. Recreate JavaScript memory views after a call or memory growth. Output views expire at the next call. Do not modify memory outside the input region, share memory, call concurrently or use atomics. Linear memory is capped at 16 MiB. A trap (including allocation failure) requires discarding the instance; this interface does not promise recovery from traps.

`python3 scripts/test-wasm-parity.py` compiles and executes both the actual C caller and WASM module. It compares the shared vectors, boundary cases and independent SHA-256 results. Node is the tested host; browser SDK packaging remains separate work. Structural validity does not authorize field names or capture, and does not remove values from raw application traffic.
