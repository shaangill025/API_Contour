//! Structure-only C ABI. Syntax validation does not authorize field names.
use contour_core::{MAX_CANONICAL_BYTES, Shape};
use std::{panic::catch_unwind, ptr, slice};

const OK: u32 = 0;
const ARGUMENT: u32 = 1;
const INPUT: u32 = 2;
const CAPACITY: u32 = 3;
const INTERNAL: u32 = 4;

/// C layout is defined in `include/contour.h`. Lengths exclude any NUL terminator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContourResult {
    pub status: u32,
    pub canonical_length: usize,
    pub fingerprint_length: usize,
}
impl ContourResult {
    fn error(status: u32) -> Self {
        Self {
            status,
            canonical_length: 0,
            fingerprint_length: 0,
        }
    }
}

fn region(address: usize, length: usize) -> Option<(usize, usize)> {
    address.checked_add(length).map(|end| (address, end))
}
fn overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1
}

/// Decode bounded structure-only wire JSON and copy canonical bytes and a
/// 64-byte lowercase hexadecimal fingerprint into caller-owned buffers.
/// Nothing is written on error. CAPACITY returns required lengths for valid
/// input; all other errors return zero lengths. Null outputs with zero capacity
/// are permitted for a size query. No Rust allocation crosses the boundary.
///
/// # Safety
/// Numeric, null and overlap checks run before any dereference. If these checks
/// succeed, input must be valid readable memory for its full length, and outputs
/// must be valid writable memory for their stated capacities. The caller must
/// prevent concurrent access during the call. Pointers must belong to live
/// allocations; integer/null checks cannot establish native pointer validity.
/// Oversized input is rejected without dereferencing any pointer. Unwinding
/// panics are caught; process abort, OOM and invalid native memory are not caught.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn contour_shape_v1(
    input: *const u8,
    input_length: usize,
    canonical: *mut u8,
    canonical_capacity: usize,
    fingerprint: *mut u8,
    fingerprint_capacity: usize,
) -> ContourResult {
    if input_length > MAX_CANONICAL_BYTES {
        return ContourResult::error(INPUT);
    }
    if input.is_null()
        || (canonical.is_null() && canonical_capacity != 0)
        || (fingerprint.is_null() && fingerprint_capacity != 0)
    {
        return ContourResult::error(ARGUMENT);
    }
    let Some(input_region) = region(input as usize, input_length) else {
        return ContourResult::error(ARGUMENT);
    };
    let Some(canonical_region) = region(canonical as usize, canonical_capacity) else {
        return ContourResult::error(ARGUMENT);
    };
    let Some(fingerprint_region) = region(fingerprint as usize, fingerprint_capacity) else {
        return ContourResult::error(ARGUMENT);
    };
    if overlap(input_region, canonical_region)
        || overlap(input_region, fingerprint_region)
        || overlap(canonical_region, fingerprint_region)
    {
        return ContourResult::error(ARGUMENT);
    }
    catch_unwind(|| {
        // SAFETY: the caller guarantees a readable live region; length is bounded
        // before constructing a slice. Outputs have not been borrowed or written.
        let bytes = unsafe { slice::from_raw_parts(input, input_length) };
        let Ok(shape) = Shape::from_wire_json(bytes) else {
            return ContourResult::error(INPUT);
        };
        let (Ok(encoded), Ok(hash)) = (shape.canonical_bytes(), shape.fingerprint()) else {
            return ContourResult::error(INPUT);
        };
        let mut result = ContourResult {
            status: CAPACITY,
            canonical_length: encoded.len(),
            fingerprint_length: hash.len(),
        };
        if canonical_capacity < encoded.len() || fingerprint_capacity < hash.len() {
            return result;
        }
        // SAFETY: capacities cover both computed outputs. The caller guarantees
        // live writable disjoint regions; sources are separate owned allocations.
        unsafe {
            ptr::copy_nonoverlapping(encoded.as_ptr(), canonical, encoded.len());
            ptr::copy_nonoverlapping(hash.as_ptr(), fingerprint, hash.len());
        }
        result.status = OK;
        result
    })
    .unwrap_or_else(|_| ContourResult::error(INTERNAL))
}
