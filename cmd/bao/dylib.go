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
	for i, path := range dylibLibraries {
		handles[i], _ = purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
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
			if b.library >= 0 { library = dylibLibraries[b.library] }
			panic("bao: dylib import " + b.name + " is unavailable from " + library)
		}
		if address != 0 { address = uintptr(int64(address) + b.addend) }
		*word(b.slot) = uint64(address)
	}
	for _, d := range dylibTLVDescriptors { *word(d), *word(d + 8) = uint64(tlsAddress_thunk()), 0 }
	for _, s := range dylibDataSegments {
		if mprotect(base+uintptr(s.start), uintptr(s.end-s.start), s.prot) != 0 { panic("bao: dylib page protection failed") }
	}
	for _, f := range dylibFDEs { registerFrame(base + uintptr(f)) }
	n := tlsEnd - tlsStart
	if n == 0 { n = 8 }
	buffer := make([]byte, n+tlsAlign)
	offset := (tlsAlign - uintptr(unsafe.Pointer(&buffer[0]))%%tlsAlign) %% tlsAlign
	dylibTLSTemplate = buffer[offset : offset+n]
	copy(dylibTLSTemplate, image[tlsStart:tlsData])
	return uintptr(unsafe.Pointer(&dylibTLSTemplate[0])), n, tlsAlign
}

// dylibInitialize runs the dylib's initializers in order.
func dylibInitialize() {
	var callConstructor func(uintptr)
	purego.RegisterFunc(&callConstructor, nativeDylibConstructorCaller())
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
