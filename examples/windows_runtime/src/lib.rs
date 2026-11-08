// SPDX-License-Identifier: Apache-2.0
#![no_std]
use core::sync::atomic::{AtomicU64, Ordering};
static DROPS: AtomicU64 = AtomicU64::new(0);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_windows_rust_run(value: u64) -> u64 {
    if unsafe { GetCurrentProcessId() } == 0 { return 0; }
    struct Guard;
    impl Drop for Guard { fn drop(&mut self) { DROPS.fetch_add(1, Ordering::SeqCst); } }
    { let _guard = Guard; }
    if DROPS.load(Ordering::SeqCst) == 1 { value + 1 } else { 0 }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop { core::hint::spin_loop() } }
