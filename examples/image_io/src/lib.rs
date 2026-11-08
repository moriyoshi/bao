//! Encode an in-memory bitmap as PNG, decode it, and verify every rendered pixel.
use std::ffi::c_void;
use std::ptr::{null, null_mut};
type Ref = *const c_void;
#[repr(C)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(a: Ref, bytes: *const u8, len: isize, enc: u32, external: u8)
    -> Ref;
    fn CFDataCreateMutable(a: Ref, capacity: isize) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    fn CFRelease(value: Ref);
}
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> Ref;
    fn CGColorSpaceRelease(space: Ref);
    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits: usize,
        stride: usize,
        space: Ref,
        info: u32,
    ) -> Ref;
    fn CGBitmapContextCreateImage(ctx: Ref) -> Ref;
    fn CGContextDrawImage(ctx: Ref, rect: Rect, image: Ref);
    fn CGContextRelease(ctx: Ref);
    fn CGImageRelease(image: Ref);
    fn CGImageGetWidth(image: Ref) -> usize;
    fn CGImageGetHeight(image: Ref) -> usize;
}
#[link(name = "ImageIO", kind = "framework")]
unsafe extern "C" {
    fn CGImageDestinationCreateWithData(data: Ref, kind: Ref, count: usize, options: Ref) -> Ref;
    fn CGImageDestinationAddImage(dest: Ref, image: Ref, properties: Ref);
    fn CGImageDestinationFinalize(dest: Ref) -> bool;
    fn CGImageSourceCreateWithData(data: Ref, options: Ref) -> Ref;
    fn CGImageSourceCreateImageAtIndex(source: Ref, index: usize, options: Ref) -> Ref;
}
struct Owned(Ref, unsafe extern "C" fn(Ref));
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                (self.1)(self.0)
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        let rgb = Owned(CGColorSpaceCreateDeviceRGB(), CGColorSpaceRelease);
        if rgb.0.is_null() {
            return 0;
        }
        let mut pixels = [0u8; 4 * 4 * 4];
        for pixel in pixels.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[0, 255, 0, 255]);
        }
        let ctx = Owned(
            CGBitmapContextCreate(
                pixels.as_mut_ptr().cast(),
                4,
                4,
                8,
                16,
                rgb.0,
                1 | (4 << 12),
            ),
            CGContextRelease,
        );
        if ctx.0.is_null() {
            return 1;
        }
        let image = Owned(CGBitmapContextCreateImage(ctx.0), CGImageRelease);
        let kind = Owned(
            CFStringCreateWithBytes(null(), b"public.png".as_ptr(), 10, 0x08000100, 0),
            CFRelease,
        );
        let data = Owned(CFDataCreateMutable(null(), 0), CFRelease);
        if image.0.is_null() || kind.0.is_null() || data.0.is_null() {
            return 2;
        }
        let dest = Owned(
            CGImageDestinationCreateWithData(data.0, kind.0, 1, null()),
            CFRelease,
        );
        if dest.0.is_null() {
            return 3;
        }
        CGImageDestinationAddImage(dest.0, image.0, null());
        if !CGImageDestinationFinalize(dest.0) || CFDataGetLength(data.0) < 8 {
            return 4;
        }
        if std::slice::from_raw_parts(CFDataGetBytePtr(data.0), 8) != b"\x89PNG\r\n\x1a\n" {
            return 5;
        }
        let source = Owned(CGImageSourceCreateWithData(data.0, null()), CFRelease);
        if source.0.is_null() {
            return 6;
        }
        let decoded = Owned(
            CGImageSourceCreateImageAtIndex(source.0, 0, null()),
            CGImageRelease,
        );
        if decoded.0.is_null()
            || CGImageGetWidth(decoded.0) != 4
            || CGImageGetHeight(decoded.0) != 4
        {
            return 7;
        }
        let mut output = [0u8; 64];
        let out = Owned(
            CGBitmapContextCreate(
                output.as_mut_ptr().cast(),
                4,
                4,
                8,
                16,
                rgb.0,
                1 | (4 << 12),
            ),
            CGContextRelease,
        );
        if out.0 == null_mut() {
            return 8;
        }
        CGContextDrawImage(
            out.0,
            Rect {
                x: 0.0,
                y: 0.0,
                width: 4.0,
                height: 4.0,
            },
            decoded.0,
        );
        drop(out);
        if output == pixels { 42 } else { 9 }
    }
}
