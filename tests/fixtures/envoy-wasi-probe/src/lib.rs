#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    fn clock_time_get(id: u32, precision: u64, time: *mut u64) -> u16;
    fn random_get(buf: *mut u8, len: usize) -> u16;
}
#[link(wasm_import_module = "env")]
extern "C" {
    fn proxy_send_local_response(
        status: u32,
        details: *const u8,
        details_len: usize,
        body: *const u8,
        body_len: usize,
        headers: *const u8,
        headers_len: usize,
        grpc_status: i32,
    ) -> u32;
}

// Proxy-Wasm hosts may request temporary guest storage. This fixture has a fixed,
// bounded arena and deliberately never reallocates or grows it.
static mut ARENA: [u8; 65536] = [0; 65536];
static mut NEXT: usize = 0;
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    let start = (NEXT + 7) & !7;
    match start.checked_add(size) {
        Some(end) if end <= 65536 => {
            NEXT = end;
            core::ptr::addr_of_mut!(ARENA).cast::<u8>().add(start)
        }
        _ => core::ptr::null_mut(),
    }
}
#[no_mangle]
pub extern "C" fn proxy_abi_version_0_2_1() {}
#[no_mangle]
pub extern "C" fn proxy_on_context_create(_: u32, _: u32) {}
#[no_mangle]
pub extern "C" fn proxy_on_vm_start(_: u32, _: usize) -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn proxy_on_configure(_: u32, _: usize) -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn proxy_on_done(_: u32) -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn proxy_on_delete(_: u32) {}

#[no_mangle]
pub extern "C" fn proxy_on_request_headers(_: u32, _: usize, _: u32) -> u32 {
    let mut realtime = 0u64;
    let mut before = 0u64;
    let mut after = 0u64;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let ok = unsafe {
        clock_time_get(0, 1, &mut realtime) == 0
            && realtime != 0
            && clock_time_get(1, 1, &mut before) == 0
            && random_get(a.as_mut_ptr(), a.len()) == 0
            && random_get(b.as_mut_ptr(), b.len()) == 0
    };
    let mut advanced = false;
    if ok {
        for _ in 0..10_000 {
            if unsafe { clock_time_get(1, 1, &mut after) } != 0 || after < before {
                break;
            }
            if after > before {
                advanced = true;
                break;
            }
        }
    }
    if ok && advanced && a != b {
        let marker = b"wasi-probe-ok";
        let headers = [0u8; 4];
        unsafe {
            proxy_send_local_response(
                200,
                core::ptr::null(),
                0,
                marker.as_ptr(),
                marker.len(),
                headers.as_ptr(),
                headers.len(),
                -1,
            );
        }
    }
    0
}
