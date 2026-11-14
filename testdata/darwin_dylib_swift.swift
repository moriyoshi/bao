// Fixture for Bao's Swift dylib support: protocol conformances found by a
// dynamic cast, a struct and a final class adopting a protocol, a CaseIterable
// enum, collections, a thrown Swift error and a type name.
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

// out: summed areas, enum case count, conformance through a dynamic cast,
// type name length, dictionary count, caught error, enum description length.
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
}
