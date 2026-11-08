// SPDX-License-Identifier: Apache-2.0
//! Standalone Linux arm64 library: std unwinding, TLS, threads, constructors,
//! native libc imports/callbacks and strong native alignment. No Rust crates.
use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static TLS_DROPS: AtomicU64 = AtomicU64::new(0);
static UNWIND_DROPS: AtomicU64 = AtomicU64::new(0);
static INITIALIZED: AtomicU64 = AtomicU64::new(0);
static LATE_CLEANUPS: AtomicU64 = AtomicU64::new(0);
static LATE_ERRORS: AtomicU64 = AtomicU64::new(0);
static LATE_KEY: OnceLock<u32> = OnceLock::new();

struct TlsGuard;
impl Drop for TlsGuard {
    fn drop(&mut self) {
        TLS_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
thread_local! {
    static GUARD: TlsGuard = const { TlsGuard };
    static INITIAL: Cell<u64> = const { Cell::new(42) };
    static ZERO: Cell<u64> = const { Cell::new(0) };
    static ALIGNED_TLS: Aligned = const { Aligned([42; 128]) };
}

#[repr(C, align(128))]
struct Aligned([u8; 128]);
static ALIGNED: Aligned = Aligned([42; 128]);
static BYTES: [u8; 16] = [1; 16];
struct NativePointer(*const u8);
unsafe impl Sync for NativePointer {}
static INTERIOR: NativePointer = NativePointer(unsafe { BYTES.as_ptr().add(7) });

unsafe extern "C" {
    fn getpid() -> c_int;
    fn malloc(bytes: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn qsort(
        base: *mut c_void,
        count: usize,
        width: usize,
        compare: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    );
    // glibc's GLOBAL definition avoids the weak `environ` alias's differing
    // ABS64/GOT resolution in the ordinary LoongArch BFD native control.
    #[link_name = "__environ"]
    static environ: *mut *mut c_char;
    fn pthread_key_create(key: *mut u32, destructor: unsafe extern "C" fn(*mut c_void)) -> c_int;
    fn pthread_setspecific(key: u32, value: *const c_void) -> c_int;
}

// An absolute imported DATA pointer requires a native initialization fixup.
struct EnvAddress(*const *mut *mut c_char);
unsafe impl Sync for EnvAddress {}
static ENV_ADDRESS: EnvAddress = EnvAddress(&raw const environ);

extern "C" fn first(argc: c_int, argv: *const *const c_char, envp: *const *const c_char) {
    if argc > 0 && !argv.is_null() && !envp.is_null() && unsafe { !(*argv).is_null() } {
        INITIALIZED.store(17, Ordering::SeqCst);
    }
}
extern "C" fn second() {
    INITIALIZED
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| Some(n * 2 + 8))
        .unwrap();
}
#[used]
#[unsafe(link_section = ".init_array.00080")]
static FIRST: extern "C" fn(c_int, *const *const c_char, *const *const c_char) = first;
#[used]
#[unsafe(link_section = ".init_array.00081")]
static SECOND: extern "C" fn() = second;

struct UnwindGuard;
impl Drop for UnwindGuard {
    fn drop(&mut self) {
        UNWIND_DROPS.fetch_add(1, Ordering::SeqCst);
    }
}
#[inline(never)]
fn inner() {
    let _guard = UnwindGuard;
    panic!("bao Linux unwind fixture");
}
#[inline(never)]
fn middle() {
    let _guard = UnwindGuard;
    inner();
}

fn touch_tls() -> bool {
    GUARD.with(|_| {});
    if !ALIGNED_TLS.with(|value| {
        let address = std::hint::black_box(value as *const Aligned);
        (address as usize) % 128 == 0 && unsafe { (*address).0[0] == 42 }
    }) {
        return false;
    }
    INITIAL.with(|initial| {
        ZERO.with(|zero| {
            let good = initial.get() == 42 && zero.get() == 0;
            initial.set(17);
            zero.set(9);
            good
        })
    })
}

// Runs from an independent pthread key AFTER compiler TLS destructors. The
// original native TLS allocation must still contain its dropped/modified state.
// A freed/reinitialized block would incorrectly allow GUARD access again.
unsafe extern "C" fn late_cleanup(original: *mut c_void) {
    if GUARD.try_with(|_| ()).is_ok()
        || !INITIAL.with(|cell| {
            cell.get() == 17 && (cell as *const Cell<u64>).cast::<c_void>() == original
        })
        || !ZERO.with(|cell| cell.get() == 9)
    {
        LATE_ERRORS.fetch_add(1, Ordering::SeqCst);
    }
    LATE_CLEANUPS.fetch_add(1, Ordering::SeqCst);
}
unsafe extern "C" fn compare(a: *const c_void, b: *const c_void) -> c_int {
    let a = unsafe { *(a as *const u64) };
    let b = unsafe { *(b as *const u64) };
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        _ => 1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    if INITIALIZED.load(Ordering::SeqCst) != 42 || std::env::args_os().count() == 0 {
        return 1;
    }
    let aligned = std::hint::black_box(&raw const ALIGNED);
    if (aligned as usize) % 128 != 0 || unsafe { (*aligned).0[0] != 42 } {
        return 2;
    }
    // Volatile reads ensure the linker, rather than constant folding, supplies
    // the native pointer values being tested.
    let interior = unsafe { std::ptr::read_volatile(&INTERIOR.0) };
    if interior as usize - BYTES.as_ptr() as usize != 7 {
        return 3;
    }
    let imported = unsafe { std::ptr::read_volatile(&ENV_ADDRESS.0) };
    if imported != &raw const environ {
        return 4;
    }
    unsafe {
        if getpid() <= 0 {
            return 5;
        }
        let memory = malloc(32) as *mut u64;
        if memory.is_null() {
            return 6;
        }
        for (i, value) in [9, 2, 42, 1].into_iter().enumerate() {
            memory.add(i).write(value);
        }
        qsort(memory.cast(), 4, 8, compare);
        let sorted = std::slice::from_raw_parts(memory, 4) == [1, 2, 9, 42];
        free(memory.cast());
        if !sorted {
            return 7;
        }
    }
    let mut key = 0;
    if unsafe { pthread_key_create(&mut key, late_cleanup) } != 0 || LATE_KEY.set(key).is_err() {
        return 11;
    }
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                if !touch_tls() {
                    return false;
                }
                INITIAL.with(|cell| unsafe {
                    pthread_setspecific(*LATE_KEY.get().unwrap(), (cell as *const Cell<u64>).cast())
                        == 0
                })
            })
        })
        .collect();
    for worker in workers {
        if worker.join().ok() != Some(true) {
            return 8;
        }
    }
    if TLS_DROPS.load(Ordering::SeqCst) != 8
        || LATE_CLEANUPS.load(Ordering::SeqCst) != 8
        || LATE_ERRORS.load(Ordering::SeqCst) != 0
        || !touch_tls()
    {
        return 9;
    }
    if std::panic::catch_unwind(middle).is_ok() || UNWIND_DROPS.load(Ordering::SeqCst) != 2 {
        return 10;
    }
    42
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_check_finalized() -> u64 {
    if TLS_DROPS.load(Ordering::SeqCst) == 9 && UNWIND_DROPS.load(Ordering::SeqCst) == 2 {
        42
    } else {
        0
    }
}
