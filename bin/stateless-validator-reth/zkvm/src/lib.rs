//! Reth stateless validator guest program for every zkVM.
//!
//! The zkVM SDK it is linked against provides `_start`, `read_input`, `write_output` and the
//! `zkvm_*` accelerators of the zkvm-standards, plus the two symbols below, which this crate uses
//! as the guest's runtime.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};

use ere_platform_core::Platform;
use stateless_validator_reth::guest::entrypoint;

unsafe extern "C" {
    /// The zkVM's heap: `bytes` bytes aligned to `align`, never freed.
    fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;
    /// Failed termination.
    fn abort() -> !;
}

struct SdkHeap;

unsafe impl GlobalAlloc for SdkHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { sys_alloc_aligned(layout.size(), layout.align()) }
    }

    // The SDK's heap does not free.
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static HEAP: SdkHeap = SdkHeap;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}

/// Input and output through the standard `read_input` and `write_output`.
#[derive(Debug)]
struct ZkvmPlatform;

impl Platform for ZkvmPlatform {}

#[unsafe(no_mangle)]
extern "C" fn main() -> i32 {
    entrypoint::<ZkvmPlatform>();
    0
}

// zkVM guests execute on one thread, so critical sections need no runtime synchronization.
#[unsafe(no_mangle)]
fn _critical_section_1_0_acquire() -> u64 {
    0
}

#[unsafe(no_mangle)]
fn _critical_section_1_0_release(_: u64) {}
