//! Reth stateless validator guest program, for every zkVM.

use ere_platform_zkvm::{ZkvmPlatform, run};
use stateless_validator_reth::guest::entrypoint;

#[unsafe(no_mangle)]
extern "C" fn main() -> i32 {
    run(entrypoint::<ZkvmPlatform>)
}

// zkVM guests execute on one thread, so critical sections need no runtime synchronization.
#[unsafe(no_mangle)]
fn _critical_section_1_0_acquire() -> u64 {
    0
}

#[unsafe(no_mangle)]
fn _critical_section_1_0_release(_: u64) {}
