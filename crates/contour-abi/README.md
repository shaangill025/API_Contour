# Native structural interface

`contour_shape_v1` accepts the same structure-only JSON as `contour_core::Shape`.
It returns the core's canonical bytes and versioned SHA-256 fingerprint through
caller-owned buffers. It does not extract raw observations, authorize names,
enroll a collector, or supply a complete collector SDK.

The input limit is 65,536 bytes. Canonical output is independently bounded to
65,536 bytes; the fingerprint contains 64 lowercase hexadecimal bytes. Neither
output has a NUL terminator. Call with null output pointers and zero capacities
to obtain required sizes, then supply disjoint buffers. A failed call writes no
output. Numeric status codes and C layout are defined in [contour.h](include/contour.h).

The C caller must supply valid live memory and prevent concurrent access. The
library rejects null, overflowing and overlapping regions, but cannot validate
arbitrary native pointers. Invalid native memory is a caller contract violation.
Unwinding Rust panics do not cross the C boundary; process aborts and allocation
failure are not recoverable guarantees. No Rust handles or allocations escape.

Run `python3 scripts/test-native-abi.py` from the repository root. It compiles an
actual C executable, links the library, checks the shared reference corpus and
independently computes the domain-separated hashes. It also checks invalid
structures, input/output limits and buffer guards. This verifies the current
native host only. Linux and macOS are separate CI executions; WebAssembly parity
requires its own compiled module and execution evidence.
