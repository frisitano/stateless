//! Reth stateless validator guest program for every zkVM, on [`ere_platform_zkvm`].

#![no_std]

use critical_section::RawRestoreState;
use ere_platform_zkvm::ZkvmPlatform;
use stateless_validator_reth::guest::entrypoint;

#[unsafe(no_mangle)]
extern "C" fn main() -> i32 {
    entrypoint::<ZkvmPlatform>();
    0
}

/// The guest runs on one thread, without interrupts, so critical sections exclude nothing.
struct SingleThread;
critical_section::set_impl!(SingleThread);

unsafe impl critical_section::Impl for SingleThread {
    unsafe fn acquire() -> RawRestoreState {}

    unsafe fn release(_: RawRestoreState) {}
}
