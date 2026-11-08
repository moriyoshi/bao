//! A standalone std archive: constructors, panics/RAII, TLS, threads, alignment.
use std::cell::Cell;
use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFAbsoluteTimeGetCurrent() -> f64;
    static kCFAllocatorDefault: *const c_void;
}
unsafe extern "C" {
    fn pthread_main_np() -> i32;
}
static INITIALIZED: AtomicU64 = AtomicU64::new(0);
static TLS_DROPS: AtomicU64 = AtomicU64::new(0);
static UNWIND_DROPS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn first(argc: i32, argv: *const *const c_char, env: *const *const c_char) {
    if argc > 0
        && !argv.is_null()
        && !env.is_null()
        && unsafe { !(*argv).is_null() && pthread_main_np() != 0 }
    {
        INITIALIZED.store(17, SeqCst);
    }
}
unsafe extern "C" fn second(_: i32, _: *const *const c_char, _: *const *const c_char) {
    INITIALIZED.store(INITIALIZED.load(SeqCst) * 2 + 8, SeqCst);
}
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static CTORS: [unsafe extern "C" fn(i32, *const *const c_char, *const *const c_char); 2] =
    [first, second];

// Force native data-pointer fixups and a pointer addend independent of gpui-go.
struct Pointer(*const c_void);
unsafe impl Sync for Pointer {}
static IMPORTED: Pointer = Pointer(&raw const kCFAllocatorDefault as *const c_void);
static BYTES: [u8; 16] = [1; 16];
static INTERIOR: Pointer = Pointer(unsafe { BYTES.as_ptr().add(7) }.cast());
#[repr(align(128))]
struct Aligned([u8; 128]);
static ALIGNED: Aligned = Aligned([5; 128]);

#[repr(align(128))]
struct Guard([u8; 128]);
impl Drop for Guard {
    fn drop(&mut self) {
        TLS_DROPS.fetch_add(1, SeqCst);
    }
}
thread_local! {
    static INITIAL: Cell<u64> = const { Cell::new(37) };
    static ZERO: Cell<u64> = const { Cell::new(0) };
    static GUARD: Guard = const { Guard([3; 128]) };
}
fn touch() -> bool {
    let initial = INITIAL.with(|v| {
        let old = v.get();
        v.set(old + 1);
        old
    });
    let zero = ZERO.with(|v| {
        let old = v.get();
        v.set(old + 1);
        old
    });
    initial == 37
        && zero == 0
        && GUARD.with(|g| (g as *const Guard as usize) % 128 == 0 && g.0[127] == 3)
}
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        UNWIND_DROPS.fetch_add(1, SeqCst);
    }
}
#[inline(never)]
fn inner() {
    let _cleanup = Cleanup;
    panic!("bao standalone unwind check");
}
#[inline(never)]
fn middle() {
    let _cleanup = Cleanup;
    inner();
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    if INITIALIZED.load(SeqCst) != 42 {
        return 1;
    }
    // Retain the actual storage and address instead of folding a type's known
    // alignment into a constant. The final executable is audited independently.
    let aligned = std::hint::black_box(&raw const ALIGNED);
    if (aligned as usize) % 128 != 0 || unsafe { (*aligned).0[127] } != 5 {
        return 2;
    }
    let imported = unsafe { std::ptr::read_volatile(&IMPORTED.0) };
    let interior = unsafe { std::ptr::read_volatile(&INTERIOR.0) };
    if imported != (&raw const kCFAllocatorDefault).cast()
        || interior as usize - BYTES.as_ptr() as usize != 7
    {
        return 3;
    }
    if unsafe { CFAbsoluteTimeGetCurrent() } <= 0.0 {
        return 4;
    }
    let threads: Vec<_> = (0..8).map(|_| std::thread::spawn(touch)).collect();
    for thread in threads {
        if !thread.join().unwrap_or(false) {
            return 5;
        }
    }
    if TLS_DROPS.load(SeqCst) != 8 || !touch() {
        return 6;
    }
    if std::panic::catch_unwind(middle).is_ok() || UNWIND_DROPS.load(SeqCst) != 2 {
        return 7;
    }
    42
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_check_finalized() -> u64 {
    if TLS_DROPS.load(SeqCst) == 9 { 42 } else { 0 }
}
