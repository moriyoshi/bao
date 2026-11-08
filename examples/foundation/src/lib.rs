//! Runtime-created NSString messages; no compiled ObjC class/image metadata.
use std::ffi::{CStr, c_char, c_void};
type Id = *mut c_void;
type Sel = *mut c_void;
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    static NSFoundationVersionNumber: f64;
}
#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    fn objc_autoreleasePoolPush() -> Id;
    fn objc_autoreleasePoolPop(pool: Id);
}

#[unsafe(no_mangle)]
pub extern "C" fn bao_example_run() -> u64 {
    unsafe {
        // Keep a real Foundation import so the linker emits its load command.
        if std::ptr::read_volatile(&raw const NSFoundationVersionNumber) <= 0.0 {
            return 1;
        }
        // Typed casts preserve the actual Objective-C call ABI. Every selector
        // below has exactly the signature used, and cannot throw for this input.
        let send: unsafe extern "C" fn(Id, Sel) -> Id =
            std::mem::transmute(objc_msgSend as *const ());
        let from_utf8: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
            std::mem::transmute(objc_msgSend as *const ());
        let utf8: unsafe extern "C" fn(Id, Sel) -> *const c_char =
            std::mem::transmute(objc_msgSend as *const ());
        let length: unsafe extern "C" fn(Id, Sel) -> usize =
            std::mem::transmute(objc_msgSend as *const ());
        let pool = objc_autoreleasePoolPush();
        let class = objc_getClass(c"NSString".as_ptr());
        let text = from_utf8(
            class,
            sel_registerName(c"stringWithUTF8String:".as_ptr()),
            c"Bao frameworks".as_ptr(),
        );
        let upper = send(text, sel_registerName(c"uppercaseString".as_ptr()));
        let bytes = utf8(upper, sel_registerName(c"UTF8String".as_ptr()));
        let valid = !text.is_null()
            && !upper.is_null()
            && !bytes.is_null()
            && CStr::from_ptr(bytes).to_bytes() == b"BAO FRAMEWORKS"
            && length(upper, sel_registerName(c"length".as_ptr())) == 14;
        objc_autoreleasePoolPop(pool);
        if valid { 42 } else { 0 }
    }
}
