// Keep the default unwind strategy. Linked alongside the real GPUI archive by
// the explicit runtime verification; no standalone replacement panic runtime.
use std::sync::atomic::{AtomicU64, Ordering};

static DROPPED: AtomicU64 = AtomicU64::new(0);

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

#[inline(never)]
fn inner() {
    let _guard = Guard;
    panic!("bao unwind fixture");
}

#[inline(never)]
fn middle() {
    let _guard = Guard;
    inner();
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_catch_panic() -> u64 {
    let before = DROPPED.load(Ordering::SeqCst);
    if std::panic::catch_unwind(middle).is_err()
        && DROPPED.load(Ordering::SeqCst) == before + 2
    {
        42
    } else {
        0
    }
}
