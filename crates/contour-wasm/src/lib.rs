//! Integer-only structure interface for one unshared WASM instance.
#![cfg(target_arch = "wasm32")]
#[cfg(target_feature = "atomics")]
compile_error!("contour-wasm requires unshared, single-threaded linear memory");
use contour_core::{MAX_CANONICAL_BYTES, Shape};
use std::{ptr, slice};

static mut INPUT: [u8; MAX_CANONICAL_BYTES] = [0; MAX_CANONICAL_BYTES];
static mut CANONICAL: [u8; MAX_CANONICAL_BYTES] = [0; MAX_CANONICAL_BYTES];
static mut FINGERPRINT: [u8; 64] = [0; 64];
static mut CANONICAL_LENGTH: u32 = 0;
static mut FINGERPRINT_LENGTH: u32 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_input_v1() -> u32 {
    ptr::addr_of_mut!(INPUT) as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_canonical_v1() -> u32 {
    ptr::addr_of_mut!(CANONICAL) as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_fingerprint_v1() -> u32 {
    ptr::addr_of_mut!(FINGERPRINT) as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_capacity_v1() -> u32 {
    MAX_CANONICAL_BYTES as u32
}
#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_canonical_length_v1() -> u32 {
    // Single-threaded, unshared instance; no host imports permit reentrancy.
    unsafe { CANONICAL_LENGTH }
}
#[unsafe(no_mangle)]
pub extern "C" fn contour_wasm_fingerprint_length_v1() -> u32 {
    unsafe { FINGERPRINT_LENGTH }
}
/// Return 0 for success, 2 for rejected structural input. All lengths exclude NUL.
/// Input and output regions are fixed; every call clears prior output and input.
/// A trap invalidates the call: discard the instance. No clock or authority API.
///
/// # Safety
/// The host must use one unshared instance, complete writes to only its input
/// region before calling, and prevent concurrent/reentrant access. Read outputs
/// only after success and before the next call. Recreate views after memory grows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn contour_wasm_process_v1(length: u32) -> u32 {
    // No imported functions and no shared memory: host cannot run during this call.
    unsafe {
        CANONICAL_LENGTH = 0;
        FINGERPRINT_LENGTH = 0;
        ptr::write_bytes(
            ptr::addr_of_mut!(CANONICAL).cast::<u8>(),
            0,
            MAX_CANONICAL_BYTES,
        );
        ptr::write_bytes(ptr::addr_of_mut!(FINGERPRINT).cast::<u8>(), 0, 64);
    }
    let shape = if length as usize <= MAX_CANONICAL_BYTES {
        // Fixed, live input allocation; the bounded slice never escapes decoding.
        let bytes =
            unsafe { slice::from_raw_parts(ptr::addr_of!(INPUT).cast::<u8>(), length as usize) };
        Shape::from_wire_json(bytes).ok()
    } else {
        None
    };
    unsafe {
        ptr::write_bytes(
            ptr::addr_of_mut!(INPUT).cast::<u8>(),
            0,
            MAX_CANONICAL_BYTES,
        )
    };
    let Some(shape) = shape else { return 2 };
    let (Ok(canonical), Ok(fingerprint)) = (shape.canonical_bytes(), shape.fingerprint()) else {
        return 2;
    };
    if canonical.len() > MAX_CANONICAL_BYTES || fingerprint.len() != 64 {
        return 2;
    }
    // Both capacities verified before writing either output; no allocations escape.
    unsafe {
        ptr::copy_nonoverlapping(
            canonical.as_ptr(),
            ptr::addr_of_mut!(CANONICAL).cast::<u8>(),
            canonical.len(),
        );
        ptr::copy_nonoverlapping(
            fingerprint.as_ptr(),
            ptr::addr_of_mut!(FINGERPRINT).cast::<u8>(),
            fingerprint.len(),
        );
        CANONICAL_LENGTH = canonical.len() as u32;
        FINGERPRINT_LENGTH = fingerprint.len() as u32;
    }
    0
}
