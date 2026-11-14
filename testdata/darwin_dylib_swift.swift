// Fixture for Bao's Swift dylib support: protocol conformances found by a
// dynamic cast, a struct and a final class adopting a protocol, a CaseIterable
// enum, collections, a thrown Swift error, a type name, an NSObject subclass
// with @objc methods, a generic class, an actor, and a subclass of a class
// from a resilient framework (JSONEncoder), and an NSObject subclass from a
// resilient framework, which needs Objective-C class stubs, and a dynamic
// replacement of a function in that framework.
import BaoSwiftBase
import Foundation

public protocol Shape {
    func area() -> Double
}

struct Square: Shape {
    var side: Double
    func area() -> Double { side * side }
}

final class Box: Shape {
    let width: Double
    init(_ width: Double) { self.width = width }
    func area() -> Double { width * 2 }
}

enum Kind: String, CaseIterable {
    case a, b, c
}

enum Failure: Error {
    case bad
}

func fail() throws { throw Failure.bad }

final class Greeter: NSObject {
    @objc func hello() -> Int { 3 }
}

final class Stack<Element> {
    private var items: [Element] = []
    func push(_ item: Element) { items.append(item) }
    var count: Int { items.count }
    func reduce<R>(_ start: R, _ f: (R, Element) -> R) -> R { items.reduce(start, f) }
}

actor Counter {
    private var value = 0
    func increment() -> Int {
        value += 1
        return value
    }
}

final class CompactEncoder: JSONEncoder, @unchecked Sendable {
    override init() {
        super.init()
        outputFormatting = .sortedKeys
    }
}

final class Derived: Base {
    override func value() -> Int { super.value() + 6 }
}

@_dynamicReplacement(for: greeting())
func replacedGreeting() -> Int { 42 }

func counted() -> Int {
    let done = DispatchSemaphore(value: 0)
    let result = UnsafeMutablePointer<Int>.allocate(capacity: 1)
    defer { result.deallocate() }
    Task.detached {
        let counter = Counter()
        var last = 0
        for _ in 0..<5 { last = await counter.increment() }
        result.pointee = last
        done.signal()
    }
    done.wait()
    return result.pointee
}

// out: summed areas, enum case count, conformance through a dynamic cast,
// type name length, dictionary count, caught error, enum description length,
// an @objc method, the class found and answering through the Objective-C
// runtime, a generic class, an actor, the JSONEncoder subclass's output, and
// the stub-backed subclass's override plus 10 when found by name, and the
// base framework's call to its dynamic function, which this dylib replaces.
@_cdecl("swift_check")
public func swiftCheck(_ out: UnsafeMutablePointer<Int32>) {
    let shapes: [Shape] = [Square(side: 3), Box(4)]
    out[0] = Int32(shapes.map { $0.area() }.reduce(0, +))
    out[1] = Int32(Kind.allCases.count)
    let value: Any = Square(side: 2)
    out[2] = (value as? Shape) != nil ? 1 : 0
    out[3] = Int32(String(describing: type(of: value)).count)
    var counts = ["x": 1]
    counts["y"] = 2
    out[4] = Int32(counts.count)
    do { try fail(); out[5] = 0 } catch { out[5] = 1 }
    out[6] = Int32("\(Kind.b)".count)
    let greeter = Greeter()
    out[7] = Int32(greeter.hello())
    let found = NSClassFromString("BaoSwift.Greeter") as? NSObject.Type
    out[8] = found != nil && greeter.responds(to: #selector(Greeter.hello)) ? 1 : 0
    let stack = Stack<Int>()
    for i in 1...3 { stack.push(i) }
    out[9] = Int32(stack.reduce(0, +))
    out[10] = Int32(counted())
    let encoded = (try? CompactEncoder().encode([1, 2])).map { String(decoding: $0, as: UTF8.self) } ?? ""
    out[11] = Int32(encoded.count)
    // Looked up by name before any Swift use initializes its metadata.
    let named = NSClassFromString("BaoSwift.Derived") != nil
    out[12] = Int32(Derived().value()) + (named ? 10 : 0)
    out[13] = Int32(callGreeting())
}
