// SPDX-License-Identifier: Apache-2.0
#![no_std]
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_mix(a: u64, b: f64, pointer: *const i32, tag: i8) -> f64 {
    a as f64 + b + if pointer.is_null() { tag as f64 } else { unsafe { *pointer as f64 } }
}
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_void() {}
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_usize(value: usize) -> usize { value + 42 }
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_ref(value: &u64) -> u64 { *value }
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_optimized(value: i16, _unused: f32) -> i16 { value }
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_callback(function: extern "C" fn(u64)->u64) -> u64 { function(42) }
#[repr(C)]
pub struct Pair { pub a: u64, pub b: u64 }
#[unsafe(no_mangle)]
pub extern "C" fn infer_rust_aggregate(pair: Pair)->Pair { pair }
