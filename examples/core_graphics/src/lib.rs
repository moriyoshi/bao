//! Draw a red rectangle into owned RGBA bytes. CGRect is passed in FP registers.
use std::ffi::c_void;
use std::ptr::null_mut;

type Ref = *mut c_void;
#[repr(C)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> Ref;
    fn CGColorSpaceRelease(space: Ref);
    fn CGBitmapContextCreate(
        data: Ref,
        width: usize,
        height: usize,
        bits: usize,
        stride: usize,
        space: Ref,
        info: u32,
    ) -> Ref;
    fn CGContextSetRGBFillColor(ctx: Ref, red: f64, green: f64, blue: f64, alpha: f64);
    fn CGContextFillRect(ctx: Ref, rect: Rect);
    fn CGContextRelease(ctx: Ref);
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        let mut bytes = [0u8; 8 * 8 * 4];
        let rgb = CGColorSpaceCreateDeviceRGB();
        if rgb.is_null() {
            return 0;
        }
        // kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big: RGBA bytes.
        let ctx = CGBitmapContextCreate(bytes.as_mut_ptr().cast(), 8, 8, 8, 32, rgb, 1 | (4 << 12));
        CGColorSpaceRelease(rgb);
        if ctx == null_mut() {
            return 1;
        }
        CGContextSetRGBFillColor(ctx, 1.0, 0.0, 0.0, 1.0);
        CGContextFillRect(
            ctx,
            Rect {
                x: 0.0,
                y: 0.0,
                width: 8.0,
                height: 8.0,
            },
        );
        CGContextRelease(ctx);
        if bytes.chunks_exact(4).all(|p| p == [255, 0, 0, 255]) {
            42
        } else {
            2
        }
    }
}
