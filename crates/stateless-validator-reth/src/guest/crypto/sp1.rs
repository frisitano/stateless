use ere_platform_zkvm::accelerators::{Bytes, keccak256, keccak256_into};

#[unsafe(no_mangle)]
extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let data = unsafe { core::slice::from_raw_parts(bytes, len) };
    // The accelerator writes 8-byte-aligned output directly; alloy's output may be unaligned.
    let aligned = output.cast::<Bytes<32>>();
    if aligned.is_aligned() {
        keccak256_into(data, unsafe { &mut *aligned })
    } else {
        keccak256(data).map(|hash| unsafe { output.copy_from_nonoverlapping(hash.as_ptr(), 32) })
    }
    .expect("keccak256 failed");
}
