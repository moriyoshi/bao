// Real stable-Rust compiler TLS, built with the default unwind strategy. Const
// Cell keys do not require pulling in the rest of std's destructor registry.
use std::cell::Cell;

thread_local! {
    static COUNTER: Cell<u64> = const { Cell::new(41) };
    static ZERO: Cell<u64> = const { Cell::new(0) };
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_rust_tls_next() -> u64 {
    COUNTER.with(|value| {
        let next = value.get().wrapping_add(1);
        value.set(next);
        next
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_rust_tls_zero_next() -> u64 {
    ZERO.with(|value| {
        let next = value.get().wrapping_add(1);
        value.set(next);
        next
    })
}
