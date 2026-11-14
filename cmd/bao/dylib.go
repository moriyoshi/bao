package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/translate"
)

// dylibSource emits the loader for a dylib image linked into the executable's
// signed __TEXT segment (see translate.dylibAnchor). dylibLoad makes the
// image's data segments writable, binds them as dyld would and returns its TLS
// template; dylibInitialize runs its initializers after TLS is configured.
// Code pages are never written.
func dylibSource(src *strings.Builder, p *translate.TLSProbe) {
	d := p.Dylib
	for i, off := range d.Selected {
		fmt.Fprintf(src, "\nfunc SymbolAddr%d() uintptr { return dylibImageBase() + %#x }\n", i, off)
	}
	hex := func(v uint64) string { return fmt.Sprintf("%#x", v) }
	var data []translate.DylibSegment
	for _, s := range d.Segments {
		if s.Protect&4 == 0 {
			data = append(data, s)
		}
	}
	fmt.Fprintf(src, "\nvar dylibDataSegments = [...]struct{ start, end uint64; prot int32 }{%s}\n", goList(data, func(s translate.DylibSegment) string {
		return fmt.Sprintf("{%#x,%#x,%d}", s.Start, s.End, s.Protect)
	}))
	fmt.Fprintf(src, "\nvar dylibRebases = [...]struct{ slot, target uint64 }{%s}\n", goList(d.Rebases, func(r translate.DylibRebase) string { return fmt.Sprintf("{%#x,%#x}", r.Slot, r.Target) }))
	exports := map[string]uint64{}
	for _, e := range d.Exports {
		exports[e.Name] = e.Offset
	}
	// Two-level namespace: each bind names its library, opened by path.
	// Binds without one (self, flat or weak lookups) use the dylib's own
	// export when it has one, else any loaded image.
	libraries := map[string]int{}
	var paths []string
	for _, b := range d.Binds {
		if b.Library != "" {
			if _, ok := libraries[b.Library]; !ok {
				libraries[b.Library] = 0
				paths = append(paths, b.Library)
			}
		}
	}
	sort.Strings(paths)
	for i, path := range paths {
		libraries[path] = i
	}
	fmt.Fprintf(src, "\nvar dylibLibraries = [...]string{%s}\n", goList(paths, strconv.Quote))
	fmt.Fprintf(src, "\nvar dylibRPaths = [...]string{%s}\n", goList(d.RPaths, strconv.Quote))
	fmt.Fprintf(src, "\nvar dylibBinds = [...]struct{ slot uint64; name string; library int; addend int64; weak bool; self int64 }{%s}\n", goList(d.Binds, func(b translate.DylibBind) string {
		self, library := int64(-1), -1
		if b.Library != "" {
			library = libraries[b.Library]
		} else if off, ok := exports[b.Name]; ok {
			self = int64(off)
		}
		return fmt.Sprintf("{%#x,%q,%d,%d,%t,%d}", b.Slot, b.Name, library, b.Addend, b.Weak, self)
	}))
	var descriptors []uint64
	tlsStart, tlsData, tlsEnd, tlsAlign := uint64(0), uint64(0), uint64(0), uint64(8)
	if t := d.TLV; t != nil {
		descriptors = t.Descriptors
		tlsStart, tlsData, tlsEnd, tlsAlign = t.Start, t.DataEnd, t.End, max(t.Alignment, 8)
	}
	fmt.Fprintf(src, "\nvar dylibTLVDescriptors = [...]uint64{%s}\n", goList(descriptors, hex))
	fmt.Fprintf(src, "\nvar dylibFDEs = [...]uint64{%s}\n", goList(d.Unwind.FDEs, hex))
	fmt.Fprintf(src, "\nvar dylibInitializers = [...]uint64{%s}\n", goList(d.Initializers, hex))
	names := make([]string, len(d.Exports))
	offsets := make([]uint64, len(d.Exports))
	for i, e := range d.Exports {
		names[i], offsets[i] = e.Name, e.Offset
	}
	fmt.Fprintf(src, "\nvar dylibExportNames = [...]string{%s}\nvar dylibExportOffsets = [...]uint64{%s}\n", goList(names, strconv.Quote), goList(offsets, hex))
	fmt.Fprintf(src, "\nconst dylibImageSize = %#x\n", d.Size)
	src.WriteString(dylibHelpersSource)
	objc := "(*dylibObjCSections)(nil)"
	if o := d.ObjC; o != nil {
		r := func(x translate.DylibRange) string { return fmt.Sprintf("dylibRange{%#x,%#x}", x.Start, x.End) }
		objc = fmt.Sprintf("&dylibObjCSections{imageInfo: %#x, selRefs: %s, classes: %s, loadClasses: %s, categories: %s, loadCategories: %s, protocols: %s, protoRefs: %s}", o.ImageInfo, r(o.SelRefs), r(o.Classes), r(o.LoadClasses), r(o.Categories), r(o.LoadCats), r(o.Protocols), r(o.ProtoRefs))
		src.WriteString(dylibObjCSource)
	} else {
		src.WriteString("\ntype dylibObjCSections struct{}\n\nfunc dylibObjCRegister(uintptr, *dylibObjCSections) {}\n\nfunc dylibObjCLoad(uintptr, *dylibObjCSections) {}\n")
	}
	fmt.Fprintf(src, "\nvar dylibObjC = %s\n", objc)
	swift := "[...][2]dylibRange{{}, {}, {}, {}}"
	if w := d.Swift; w != nil {
		r := func(x translate.DylibRange) string { return fmt.Sprintf("{%#x,%#x}", x.Start, x.End) }
		// protocols, conformances, type metadata (__swift5_types, __swift5_types2)
		swift = fmt.Sprintf("[...][2]dylibRange{{%s, {}}, {%s, {}}, {%s, %s}, {%s, {}}}", r(w.Protocols), r(w.Conformances), r(w.Types), r(w.Types2), r(w.Replacements))
	}
	if d.ObjC == nil {
		src.WriteString("\ntype dylibRange struct{ start, end uint64 }\n")
	}
	fmt.Fprintf(src, "\nvar dylibSwift = %s\n", swift)
	src.WriteString(dylibSwiftSource)
	fmt.Fprintf(src, `
// dylibTLSTemplate holds the dylib's TLS initializer after its fixups, since
// a thread-local variable may be initialized with an address.
var dylibTLSTemplate []byte

// dylibLoad binds the dylib image in place and returns its TLS template's
// address, size and alignment for Bao's TLS runtime.
func dylibLoad() (uintptr, uintptr, uintptr) {
	const size, tlsStart, tlsData, tlsEnd, tlsAlign = %#x, %#x, %#x, %#x, %d
	libc, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil { panic(err) }
	var mprotect func(uintptr, uintptr, int32) int32
	var registerFrame func(uintptr)
	purego.RegisterLibFunc(&mprotect, libc, "mprotect")
	purego.RegisterLibFunc(&registerFrame, libc, "__register_frame")
	const read, write = 1, 2
	base := dylibImageBase()
	for _, s := range dylibDataSegments {
		if mprotect(base+uintptr(s.start), uintptr(s.end-s.start), read|write) != 0 { panic("bao: dylib data segment is not writable") }
	}
	image := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	word := func(off uint64) *uint64 { return (*uint64)(unsafe.Pointer(&image[off])) }
	for _, r := range dylibRebases { *word(r.slot) = uint64(base) + r.target }
	handles := make([]uintptr, len(dylibLibraries))
	candidates := make([][]string, len(dylibLibraries))
	for i, name := range dylibLibraries {
		candidates[i] = dylibSearchPaths(name)
		for _, path := range candidates[i] {
			if handles[i], err = purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL); err == nil { break }
		}
	}
	for _, b := range dylibBinds {
		var address uintptr
		switch {
		case b.self >= 0:
			address = base + uintptr(b.self)
		case b.library >= 0 && handles[b.library] == 0:
		case b.library >= 0:
			address, _ = purego.Dlsym(handles[b.library], b.name)
		default:
			address, _ = purego.Dlsym(purego.RTLD_DEFAULT, b.name)
		}
		if address == 0 && !b.weak {
			library := "any loaded image"
			if b.library >= 0 { library = strings.Join(candidates[b.library], ", ") }
			panic("bao: dylib import " + b.name + " is unavailable from " + library)
		}
		if address != 0 { address = uintptr(int64(address) + b.addend) }
		*word(b.slot) = uint64(address)
	}
	for _, d := range dylibTLVDescriptors { *word(d), *word(d + 8) = uint64(tlsAddress_thunk()), 0 }
	// libobjc may write the image's selector and protocol references. Swift
	// classes are Objective-C classes, so libobjc reads them first.
	dylibObjCRegister(base, dylibObjC)
	dylibSwiftRegister(base)
	for _, s := range dylibDataSegments {
		if mprotect(base+uintptr(s.start), uintptr(s.end-s.start), s.prot) != 0 { panic("bao: dylib page protection failed") }
	}
	for _, f := range dylibFDEs { registerFrame(base + uintptr(f)) }
	n := uintptr(tlsEnd - tlsStart)
	if n == 0 { n = 8 }
	buffer := make([]byte, n+tlsAlign)
	offset := (tlsAlign - uintptr(unsafe.Pointer(&buffer[0]))%%tlsAlign) %% tlsAlign
	dylibTLSTemplate = buffer[offset : offset+n]
	copy(dylibTLSTemplate, image[tlsStart:tlsData])
	return uintptr(unsafe.Pointer(&dylibTLSTemplate[0])), n, tlsAlign
}

// dylibSearchPaths expands a dependency's install name as dyld would for an
// image of this executable: @executable_path and @loader_path name the
// executable's directory, and @rpath tries the dylib's LC_RPATH entries in
// order, each expanded the same way. dlopen itself would resolve them against
// its caller, which has no rpaths.
func dylibSearchPaths(name string) []string {
	dir := ""
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil { exe = real }
		dir = filepath.Dir(exe)
	}
	expand := func(path string) string {
		for _, prefix := range []string{"@executable_path", "@loader_path"} {
			if rest, ok := strings.CutPrefix(path, prefix); ok { return dir + rest }
		}
		return path
	}
	if rest, ok := strings.CutPrefix(name, "@rpath"); ok {
		var paths []string
		for _, rpath := range dylibRPaths { paths = append(paths, expand(rpath)+rest) }
		return paths
	}
	return []string{expand(name)}
}

// dylibInitialize runs the dylib's initializers in order.
func dylibInitialize() {
	var callConstructor func(uintptr)
	purego.RegisterFunc(&callConstructor, nativeDylibConstructorCaller())
	// dyld runs an image's +load methods before its initializers.
	dylibObjCLoad(dylibImageBase(), dylibObjC)
	for _, f := range dylibInitializers { callConstructor(dylibImageBase() + uintptr(f)) }
}

// SharedObjectExport returns the run-time address of a dylib export.
func SharedObjectExport(name string) (uintptr, bool) {
	i := sort.SearchStrings(dylibExportNames[:], name)
	if i == len(dylibExportNames) || dylibExportNames[i] != name { return 0, false }
	return dylibImageBase() + uintptr(dylibExportOffsets[i]), true
}

// SharedObjectExports lists the dylib's exported names, sorted.
func SharedObjectExports() []string { return append([]string(nil), dylibExportNames[:]...) }
`, d.Size, tlsStart, tlsData, tlsEnd, tlsAlign)
}

// dylibObjCSource registers a dylib's Objective-C metadata with libobjc
// through its public API, in the order libobjc's own image loading uses:
// selectors, protocols, classes (superclasses first), categories, then +load.
const dylibObjCSource = `
type dylibRange struct{ start, end uint64 }

type dylibObjCSections struct {
	imageInfo                                                                   uint64
	selRefs, classes, loadClasses, categories, loadCategories, protocols, protoRefs dylibRange
}

var dylibObjCRuntime struct {
	once                                                    bool
	selRegisterName                                         func(string) uintptr
	readClassPair                                           func(uintptr, uintptr) uintptr
	getProtocol, allocateProtocol                           func(string) uintptr
	addMethodDescription                                    func(uintptr, uintptr, uintptr, bool, bool)
	addProtocolToProtocol                                   func(uintptr, uintptr)
	registerProtocol                                        func(uintptr)
	replaceMethod                                           func(uintptr, uintptr, uintptr, uintptr) uintptr
	replaceProperty                                         func(uintptr, uintptr, uintptr, uint32)
	addProtocol                                             func(uintptr, uintptr) bool
	getClass                                                func(uintptr) uintptr
	msgSend                                                 func(uintptr, uintptr) uintptr
	loads                                                   [][2]uintptr // receiver, IMP
}


// dylibClassRO returns a class's class_ro_t; the data word's low bits are flags.
func dylibClassRO(cls uintptr) uintptr { return dylibWord(cls+32) & 0x00007ffffffffff8 }

// dylibMethods visits a method_list_t: pointer entries {SEL, types, IMP}, or
// relative entries {selector reference, types, IMP} when bit 31 of the
// entry size word is set. Pointer entries name their selector by string.
func dylibMethods(list uintptr, f func(sel, imp, types uintptr)) {
	if list == 0 { return }
	o := &dylibObjCRuntime
	flags, count := dylibU32(list), uintptr(dylibU32(list+4))
	size := uintptr(flags & 0xfffc)
	for i := uintptr(0); i < count; i++ {
		m := list + 8 + i*size
		if flags&0x80000000 != 0 {
			f(dylibWord(m+dylibI32(m)), m+8+dylibI32(m+8), m+4+dylibI32(m+4))
		} else {
			f(o.selRegisterName(dylibString(dylibWord(m))), dylibWord(m+16), dylibWord(m+8))
		}
	}
}

func dylibObjCRegister(base uintptr, s *dylibObjCSections) {
	o := &dylibObjCRuntime
	libobjc, err := purego.Dlopen("/usr/lib/libobjc.A.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil { panic(err) }
	for name, f := range map[string]any{"sel_registerName": &o.selRegisterName, "objc_readClassPair": &o.readClassPair, "objc_getProtocol": &o.getProtocol, "objc_allocateProtocol": &o.allocateProtocol, "protocol_addMethodDescription": &o.addMethodDescription, "protocol_addProtocol": &o.addProtocolToProtocol, "objc_registerProtocol": &o.registerProtocol, "class_replaceMethod": &o.replaceMethod, "class_replaceProperty": &o.replaceProperty, "class_addProtocol": &o.addProtocol, "object_getClass": &o.getClass, "objc_msgSend": &o.msgSend} {
		purego.RegisterLibFunc(f, libobjc, name)
	}
	each := func(r dylibRange, f func(slot uintptr)) {
		for off := r.start; off < r.end; off += 8 { f(base + uintptr(off)) }
	}
	inImage := func(p uintptr) bool { return p >= base && p < base+dylibImageSize }
	// Selector references hold method-name strings until uniqued.
	each(s.selRefs, func(slot uintptr) { *(*uintptr)(unsafe.Pointer(slot)) = o.selRegisterName(dylibString(dylibWord(slot))) })
	// Protocols: an existing protocol of the same name wins, as in libobjc.
	protocols := map[uintptr]uintptr{}
	var protocol func(p uintptr) uintptr
	protocol = func(p uintptr) uintptr {
		if !inImage(p) { return p }
		if r, ok := protocols[p]; ok { return r }
		name := dylibString(dylibWord(p + 8))
		if r := o.getProtocol(name); r != 0 {
			protocols[p] = r
			return r
		}
		r := o.allocateProtocol(name)
		if r == 0 { panic("bao: Objective-C protocol " + name + " cannot be allocated") }
		protocols[p] = r
		if list := dylibWord(p + 16); list != 0 {
			for i := uintptr(0); i < dylibWord(list); i++ { o.addProtocolToProtocol(r, protocol(dylibWord(list+8+8*i))) }
		}
		for i, kind := range [4][2]bool{{true, true}, {true, false}, {false, true}, {false, false}} {
			dylibMethods(dylibWord(p+24+8*uintptr(i)), func(sel, imp, types uintptr) { o.addMethodDescription(r, sel, types, kind[0], kind[1]) })
		}
		o.registerProtocol(r)
		return r
	}
	each(s.protocols, func(slot uintptr) { *(*uintptr)(unsafe.Pointer(slot)) = protocol(dylibWord(slot)) })
	each(s.protoRefs, func(slot uintptr) { *(*uintptr)(unsafe.Pointer(slot)) = protocol(dylibWord(slot)) })
	// Classes: superclasses first; a superclass from another image must be
	// realized, which a message send ensures.
	loadIMP := func(list uintptr) uintptr {
		load, imp := o.selRegisterName("load"), uintptr(0)
		dylibMethods(list, func(sel, i, _ uintptr) {
			if sel == load { imp = i }
		})
		return imp
	}
	loads := map[uintptr]uintptr{}
	each(s.loadClasses, func(slot uintptr) {
		cls := dylibWord(slot)
		loads[cls] = loadIMP(dylibWord(dylibClassRO(dylibWord(cls)) + 32))
	})
	done := map[uintptr]bool{}
	var read func(cls uintptr)
	read = func(cls uintptr) {
		if done[cls] { return }
		done[cls] = true
		if super := dylibWord(cls + 8); super != 0 {
			if inImage(super) {
				read(super)
			} else {
				o.msgSend(super, o.selRegisterName("self"))
			}
		}
		if o.readClassPair(cls, base+uintptr(s.imageInfo)) != cls {
			panic("bao: libobjc did not read Objective-C class " + dylibString(dylibWord(dylibClassRO(cls)+24)))
		}
		if imp := loads[cls]; imp != 0 { o.loads = append(o.loads, [2]uintptr{cls, imp}) }
	}
	each(s.classes, func(slot uintptr) { read(dylibWord(slot)) })
	// Category properties: property_list_t entries are {name, attributes}. An
	// attribute string such as T@"NSString",&,N,V_name is comma-separated
	// one-letter names, each followed by its value; type encodings contain no
	// commas. class_replaceProperty copies what it is given.
	properties := func(cls, list uintptr) {
		if list == 0 { return }
		size, count := uintptr(dylibU32(list)&0xffff), uintptr(dylibU32(list+4))
		for i := uintptr(0); i < count; i++ {
			p := list + 8 + i*size
			var keep [][]byte
			var pairs []uintptr
			for _, attr := range strings.Split(dylibString(dylibWord(p+8)), ",") {
				if attr == "" { continue }
				name, value := append([]byte(attr[:1]), 0), append([]byte(attr[1:]), 0)
				keep = append(keep, name, value)
				pairs = append(pairs, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&value[0])))
			}
			var array uintptr
			if len(pairs) != 0 { array = uintptr(unsafe.Pointer(&pairs[0])) }
			o.replaceProperty(cls, dylibWord(p), array, uint32(len(pairs)/2))
			runtime.KeepAlive(keep)
			runtime.KeepAlive(pairs)
		}
	}
	// Category class properties exist when the image info says so
	// (OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES).
	classProperties := s.imageInfo != 0 && dylibU32(base+uintptr(s.imageInfo)+4)&(1<<6) != 0
	// Categories replace and add methods, as attached categories do.
	isLoadCategory := map[uintptr]bool{}
	each(s.loadCategories, func(slot uintptr) { isLoadCategory[dylibWord(slot)] = true })
	each(s.categories, func(slot uintptr) {
		cat := dylibWord(slot)
		cls := dylibWord(cat + 8)
		if cls == 0 { panic("bao: Objective-C category " + dylibString(dylibWord(cat)) + " names an unavailable class") }
		meta := o.getClass(cls)
		dylibMethods(dylibWord(cat+16), func(sel, imp, types uintptr) { o.replaceMethod(cls, sel, imp, types) })
		dylibMethods(dylibWord(cat+24), func(sel, imp, types uintptr) { o.replaceMethod(meta, sel, imp, types) })
		if list := dylibWord(cat + 32); list != 0 {
			for i := uintptr(0); i < dylibWord(list); i++ { o.addProtocol(cls, protocol(dylibWord(list+8+8*i))) }
		}
		properties(cls, dylibWord(cat+40))
		if classProperties { properties(meta, dylibWord(cat+48)) }
		if isLoadCategory[cat] {
			if imp := loadIMP(dylibWord(cat + 24)); imp != 0 { o.loads = append(o.loads, [2]uintptr{cls, imp}) }
		}
	})
}

// dylibObjCLoad runs +load methods: classes, superclasses first, then categories.
func dylibObjCLoad(base uintptr, s *dylibObjCSections) {
	o := &dylibObjCRuntime
	load := o.selRegisterName("load")
	for _, l := range o.loads {
		var call func(uintptr, uintptr)
		purego.RegisterFunc(&call, l[1])
		call(l[0], load)
	}
}
`

// dylibSwiftSource hands the image's Swift protocol, conformance and type
// records to libswiftCore.
const dylibSwiftSource = `
func dylibSwiftRegister(base uintptr) {
	empty := true
	for _, kind := range dylibSwift {
		for _, r := range kind {
			empty = empty && r.end == r.start
		}
	}
	if empty { return }
	lib, err := purego.Dlopen("/usr/lib/swift/libswiftCore.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil { panic(err) }
	for i, name := range []string{"swift_registerProtocols", "swift_registerProtocolConformances", "swift_registerTypeMetadataRecords"} {
		var register func(uintptr, uintptr)
		purego.RegisterLibFunc(&register, lib, name)
		for _, r := range dylibSwift[i] {
			if r.end > r.start { register(base+uintptr(r.start), base+uintptr(r.end)) }
		}
	}
	// Automatic dynamic replacements, as dyld's image callback enables them.
	if r := dylibSwift[3][0]; r.end > r.start {
		var enable func(uintptr)
		purego.RegisterLibFunc(&enable, lib, "swift_enableDynamicReplacementScope")
		for p := base + uintptr(r.start); p+8 <= base+uintptr(r.end); {
			n := uintptr(dylibU32(p + 4))
			for i := uintptr(0); i < n; i++ {
				field := p + 8 + 4*i
				enable(field + dylibI32(field))
			}
			p += 8 + 4*n
		}
	}
}
`

// dylibHelpersSource reads the image's metadata in place.
const dylibHelpersSource = `
func dylibWord(p uintptr) uintptr { return *(*uintptr)(unsafe.Pointer(p)) }
func dylibU32(p uintptr) uint32   { return *(*uint32)(unsafe.Pointer(p)) }
func dylibI32(p uintptr) uintptr  { return uintptr(int64(*(*int32)(unsafe.Pointer(p)))) }
func dylibString(p uintptr) string {
	n := 0
	for *(*byte)(unsafe.Pointer(p + uintptr(n))) != 0 { n++ }
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
}
`
