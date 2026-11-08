//! Check strided vDSP vector addition and dot products against scalar Rust.
#[link(name = "Accelerate", kind = "framework")]
unsafe extern "C" {
    fn vDSP_vaddD(
        a: *const f64,
        ia: isize,
        b: *const f64,
        ib: isize,
        c: *mut f64,
        ic: isize,
        n: usize,
    );
    fn vDSP_dotprD(a: *const f64, ia: isize, b: *const f64, ib: isize, out: *mut f64, n: usize);
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    let a: Vec<f64> = (0..128).map(|i| f64::from(i) * 0.25).collect();
    let b: Vec<f64> = (0..128).map(|i| 3.0 - f64::from(i) * 0.125).collect();
    let mut c = vec![0.0; 64];
    let mut dot = 0.0;
    unsafe {
        vDSP_vaddD(a.as_ptr(), 2, b.as_ptr(), 2, c.as_mut_ptr(), 1, 64);
        vDSP_dotprD(a.as_ptr(), 2, b.as_ptr(), 2, &mut dot, 64);
    }
    let expected: f64 = (0..64).map(|i| a[2 * i] * b[2 * i]).sum();
    if (dot - expected).abs() < 1e-9 && (0..64).all(|i| (c[i] - a[2 * i] - b[2 * i]).abs() < 1e-9) {
        42
    } else {
        0
    }
}
