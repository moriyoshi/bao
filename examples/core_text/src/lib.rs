//! Resolve real font glyphs and verify summed advances against individual metrics.
use std::ffi::c_void;
use std::ptr::null;
type Ref = *const c_void;
#[repr(C)]
#[derive(Clone, Copy)]
struct Size {
    width: f64,
    height: f64,
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(a: Ref, bytes: *const u8, len: isize, enc: u32, external: u8)
    -> Ref;
    fn CFRelease(value: Ref);
}
#[link(name = "CoreText", kind = "framework")]
unsafe extern "C" {
    fn CTFontCreateWithName(name: Ref, size: f64, matrix: Ref) -> Ref;
    fn CTFontGetGlyphsForCharacters(
        font: Ref,
        chars: *const u16,
        glyphs: *mut u16,
        count: isize,
    ) -> bool;
    fn CTFontGetAdvancesForGlyphs(
        font: Ref,
        orientation: u32,
        glyphs: *const u16,
        advances: *mut Size,
        count: isize,
    ) -> f64;
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        let name = CFStringCreateWithBytes(null(), b"Helvetica".as_ptr(), 9, 0x08000100, 0);
        if name.is_null() {
            return 0;
        }
        let font = CTFontCreateWithName(name, 24.0, null());
        CFRelease(name);
        if font.is_null() {
            return 1;
        }
        let chars = [b'B' as u16, b'a' as u16, b'o' as u16];
        let mut glyphs = [0u16; 3];
        let mapped = CTFontGetGlyphsForCharacters(font, chars.as_ptr(), glyphs.as_mut_ptr(), 3);
        let mut advances = [Size {
            width: 0.0,
            height: 0.0,
        }; 3];
        let width = CTFontGetAdvancesForGlyphs(font, 0, glyphs.as_ptr(), advances.as_mut_ptr(), 3);
        CFRelease(font);
        if mapped
            && glyphs.iter().all(|&g| g != 0)
            && width.is_finite()
            && width > 0.0
            && advances.iter().all(|s| s.width > 0.0)
            && (width - advances.iter().map(|s| s.width).sum::<f64>()).abs() < 1e-9
        {
            42
        } else {
            2
        }
    }
}
