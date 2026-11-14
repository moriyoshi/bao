// Resilient base framework for darwin_dylib_swift.swift: an open NSObject
// subclass built with library evolution, so a subclass in another module
// needs Objective-C class stubs, and a dynamic function the fixture replaces.
import Foundation

open class Base: NSObject {
    public override init() { super.init() }
    open func value() -> Int { 1 }
}

public dynamic func greeting() -> Int { 1 }

// Calls greeting() from this framework, so a replacement must be in force
// process-wide to change the result.
public func callGreeting() -> Int { greeting() }
