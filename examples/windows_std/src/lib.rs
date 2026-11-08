// SPDX-License-Identifier: Apache-2.0
//! Windows std staticlib: allocation, native threads, TLS and caught unwinding.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
static INITIALIZED: AtomicU64 = AtomicU64::new(0);
static TLS_DROPS: AtomicU64 = AtomicU64::new(0);
static UNWIND_DROPS: AtomicU64 = AtomicU64::new(0);
static TLS_FAILURES: AtomicU64 = AtomicU64::new(0);
static FLS_CALLBACK_VALUE: AtomicU64 = AtomicU64::new(0);
static LOCK: Mutex<u64> = Mutex::new(0);
static TEXT: OnceLock<String> = OnceLock::new();
#[link(name = "kernel32")]
unsafe extern "system" {
    fn FlsAlloc(callback: Option<unsafe extern "system" fn(*mut std::ffi::c_void)>) -> u32;
    fn FlsGetValue(key: u32) -> *mut std::ffi::c_void;
    fn FlsSetValue(key: u32, value: *mut std::ffi::c_void) -> i32;
    fn FlsFree(key: u32) -> i32;
    fn RtlLookupFunctionEntry(
        pc: u64,
        base: *mut u64,
        history: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
}
unsafe extern "C" fn initialize() {
    INITIALIZED.store(42, SeqCst);
}
#[used]
#[unsafe(link_section = ".CRT$XCU")]
static INITIALIZER: unsafe extern "C" fn() = initialize;
#[repr(align(128))]
struct Guard([u8; 128]);
impl Drop for Guard {
    fn drop(&mut self) {
        TLS_DROPS.fetch_add(1, SeqCst);
    }
}
thread_local! {
 static VISITS: Cell<u64> = const { Cell::new(0) };
 static GUARD: Guard = const { Guard([7;128]) };
}
fn touch() -> bool {
    let first = VISITS.with(|v| {
        let old = v.get();
        v.set(old + 1);
        old == 0
    });
    let (aligned, valid) = GUARD.with(|g| {
        (
            std::hint::black_box(g as *const Guard as usize) % 128 == 0,
            g.0[127] == 7,
        )
    });
    let failures = (!first as u64) | ((!aligned as u64) << 1) | ((!valid as u64) << 2);
    TLS_FAILURES.fetch_or(failures, SeqCst);
    failures == 0
}
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        UNWIND_DROPS.fetch_add(1, SeqCst);
    }
}
#[inline(never)]
fn inner() {
    let _guard = Cleanup;
    panic!("Bao Windows std unwind control");
}
#[inline(never)]
fn middle() {
    let _guard = Cleanup;
    inner();
}
#[unsafe(no_mangle)]
pub extern "C" fn bao_windows_std_run() -> u64 {
    if INITIALIZED.load(SeqCst) != 42 {
        return 1;
    }
    let text = TEXT.get_or_init(|| String::from("Bao Windows std"));
    let values: Vec<_> = (0..128u64).collect();
    if text.len() != 15 || values.iter().sum::<u64>() != 8128 {
        return 2;
    }
    let mut map = std::collections::HashMap::new();
    map.insert(text.clone(), 42);
    if map.get(text) != Some(&42)
        || std::env::args_os().next().is_none()
        || std::env::current_dir().is_err()
    {
        return 8;
    }
    if !file_io() {
        return 9;
    }
    if !fls_roundtrip() {
        return 10;
    }
    let start = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                *LOCK.lock().unwrap() += 1;
                touch()
            })
        })
        .collect();
    for t in threads {
        if !t.join().unwrap_or(false) {
            return 3;
        }
    }
    if *LOCK.lock().unwrap() != 8 || TLS_DROPS.load(SeqCst) != 8 || !touch() {
        return 4;
    }
    let mut image = 0;
    if unsafe {
        RtlLookupFunctionEntry(inner as *const () as u64, &mut image, std::ptr::null_mut())
    }
    .is_null()
    {
        return 6;
    }
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let caught = std::panic::catch_unwind(middle).is_err();
    std::panic::set_hook(hook);
    if !caught || UNWIND_DROPS.load(SeqCst) != 2 {
        return 5;
    }
    42
}
fn file_io() -> bool {
    use std::io::{Read, Seek, SeekFrom, Write};
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    let path = std::env::temp_dir().join(format!(
        "bao-std-{}-{}.tmp",
        std::process::id(),
        now.as_nanos()
    ));
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    else {
        return false;
    };
    let result = (|| -> std::io::Result<bool> {
        file.write_all(b"Bao Windows std\0data")?;
        file.seek(SeekFrom::Start(0))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data == b"Bao Windows std\0data")
    })();
    drop(file);
    let removed = std::fs::remove_file(path).is_ok();
    result.unwrap_or(false) && removed
}
unsafe extern "system" fn fls_drop(value: *mut std::ffi::c_void) {
    FLS_CALLBACK_VALUE.fetch_add(value as u64, SeqCst);
}
fn fls_roundtrip() -> bool {
    unsafe {
        let key = FlsAlloc(Some(fls_drop));
        if key == u32::MAX {
            return false;
        }
        if FlsSetValue(key, 1usize as *mut _) == 0
            || FlsGetValue(key) as usize != 1
            || FlsSetValue(key, std::ptr::null_mut()) == 0
            || !FlsGetValue(key).is_null()
            || FLS_CALLBACK_VALUE.load(SeqCst) != 0
        {
            return false;
        }
        if FlsSetValue(key, 2usize as *mut _) == 0
            || FlsFree(key) == 0
            || FLS_CALLBACK_VALUE.load(SeqCst) != 2
        {
            return false;
        }
        let key = FlsAlloc(None);
        if key == u32::MAX {
            return false;
        }
        FlsSetValue(key, 3usize as *mut _) != 0
            && FlsGetValue(key) as usize == 3
            && FlsFree(key) != 0
            && FLS_CALLBACK_VALUE.load(SeqCst) == 2
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn bao_windows_std_check() -> u64 {
    if TLS_DROPS.load(SeqCst) == 9 {
        42
    } else {
        TLS_DROPS.load(SeqCst)
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn bao_windows_std_counts(which: u64) -> u64 {
    match which {
        0 => TLS_DROPS.load(SeqCst),
        1 => UNWIND_DROPS.load(SeqCst),
        2 => *LOCK.lock().unwrap(),
        3 => TLS_FAILURES.load(SeqCst),
        4 => FLS_CALLBACK_VALUE.load(SeqCst),
        _ => 0,
    }
}
