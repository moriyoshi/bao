// Actual std::thread_local destructor registration and std native threads.
use std::sync::atomic::{AtomicU64, Ordering};

static DROPPED: AtomicU64 = AtomicU64::new(0);

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

thread_local! { static GUARD: Guard = const { Guard }; }

#[unsafe(no_mangle)]
pub extern "C" fn bao_rust_tls_touch_drop() {
    GUARD.with(|_| {});
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_rust_tls_drop_count() -> u64 {
    DROPPED.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_rust_tls_thread_test() -> u64 {
    let before = DROPPED.load(Ordering::SeqCst);
    let mut threads = Vec::new();
    for _ in 0..8 {
        threads.push(std::thread::spawn(|| bao_rust_tls_touch_drop()));
    }
    for thread in threads {
        if thread.join().is_err() {
            return 0;
        }
    }
    if DROPPED.load(Ordering::SeqCst) == before + 8 {
        42
    } else {
        0
    }
}
