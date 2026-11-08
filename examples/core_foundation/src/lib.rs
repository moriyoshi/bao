//! Unicode CFString -> binary property list -> CFString, with owned CF objects.
use std::ffi::c_void;
use std::ptr::null;

type Ref = *const c_void;
const UTF8: u32 = 0x08000100;
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(a: Ref, bytes: *const u8, len: isize, enc: u32, external: u8)
    -> Ref;
    fn CFStringGetCString(s: Ref, buf: *mut u8, capacity: isize, enc: u32) -> u8;
    fn CFPropertyListCreateData(
        a: Ref,
        value: Ref,
        format: isize,
        options: usize,
        error: *mut Ref,
    ) -> Ref;
    fn CFPropertyListCreateWithData(
        a: Ref,
        data: Ref,
        options: usize,
        format: *mut isize,
        error: *mut Ref,
    ) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFEqual(a: Ref, b: Ref) -> u8;
    fn CFRelease(value: Ref);
}

struct Owned(Ref);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                CFRelease(self.0)
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        let text = "Bao: 日本語 🦀";
        let original = Owned(CFStringCreateWithBytes(
            null(),
            text.as_ptr(),
            text.len() as isize,
            UTF8,
            0,
        ));
        if original.0.is_null() {
            return 0;
        }
        let mut error = null();
        let data = Owned(CFPropertyListCreateData(
            null(),
            original.0,
            200,
            0,
            &mut error,
        ));
        let _error = Owned(error);
        if data.0.is_null() || CFDataGetLength(data.0) == 0 {
            return 1;
        }
        let mut format = 0;
        error = null();
        let decoded = Owned(CFPropertyListCreateWithData(
            null(),
            data.0,
            0,
            &mut format,
            &mut error,
        ));
        let _error = Owned(error);
        if decoded.0.is_null() || format != 200 || CFEqual(original.0, decoded.0) == 0 {
            return 2;
        }
        let mut buf = [0u8; 128];
        if CFStringGetCString(decoded.0, buf.as_mut_ptr(), buf.len() as isize, UTF8) == 0 {
            return 3;
        }
        if &buf[..text.len()] != text.as_bytes() || buf[text.len()] != 0 {
            return 4;
        }
        42
    }
}
