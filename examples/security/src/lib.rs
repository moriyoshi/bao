//! Fill native-owned buffers via Security's exported random-source data symbol.
use std::ffi::c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecRandomDefault: *const c_void;
    fn SecRandomCopyBytes(source: *const c_void, count: usize, bytes: *mut u8) -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        if SecRandomCopyBytes(kSecRandomDefault, a.len(), a.as_mut_ptr()) != 0
            || SecRandomCopyBytes(kSecRandomDefault, b.len(), b.as_mut_ptr()) != 0
        {
            return 0;
        }
        // Smoke check only, not an entropy or cryptographic-quality test.
        if a != b && a.iter().any(|&x| x != 0) && b.iter().any(|&x| x != 0) {
            42
        } else {
            1
        }
    }
}
