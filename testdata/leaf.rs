#![no_std]

// Deliberately only a leaf: this fixture does not exercise Rust's standard
// library, TLS, panic handling, or constructors.
#[unsafe(no_mangle)]
pub extern "C" fn bao_leaf_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}
