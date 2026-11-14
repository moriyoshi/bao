// Resilient base framework for darwin_dylib_swift.swift: an open NSObject
// subclass built with library evolution, so a subclass in another module
// needs Objective-C class stubs.
import Foundation

open class Base: NSObject {
    public override init() { super.init() }
    open func value() -> Int { 1 }
}
