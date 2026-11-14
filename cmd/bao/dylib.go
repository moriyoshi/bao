package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/translate"
)

// dylibSource emits the loader for a dylib image: dyld's steps, in its
// order, and the export table. On arm64 __TEXT goes into MAP_JIT memory,
// which macOS lets an unsigned image execute; the other segments are ordinary
// anonymous memory at their fixed distances, so they stay writable while the
// code runs.
func dylibSource(src *strings.Builder, p *translate.TLSProbe) {
	d := p.Dylib
	fmt.Fprintf(src, "\n//go:embed dylib_darwin_%s.bin\nvar dylibImage string\nvar dylibBase uintptr\n", p.Arch)
	for i, off := range d.Selected {
		fmt.Fprintf(src, "\nfunc SymbolAddr%d() uintptr { return dylibBase + %#x }\n", i, off)
	}
	hex := func(v uint64) string { return fmt.Sprintf("%#x", v) }
	fmt.Fprintf(src, "\nvar dylibSegments = [...]struct{ start, end uint64; prot int32 }{%s}\n", goList(d.Segments, func(s translate.DylibSegment) string {
		return fmt.Sprintf("{%#x,%#x,%d}", s.Start, s.End, s.Protect)
	}))
	fmt.Fprintf(src, "\nvar dylibRebases = [...]struct{ slot, target uint64 }{%s}\n", goList(d.Rebases, func(r translate.DylibRebase) string { return fmt.Sprintf("{%#x,%#x}", r.Slot, r.Target) }))
	exports := map[string]uint64{}
	for _, e := range d.Exports {
		exports[e.Name] = e.Offset
	}
	// Binds without a library ordinal (self, flat or weak lookups) use the
	// dylib's own export when it has one.
	fmt.Fprintf(src, "\nvar dylibBinds = [...]struct{ slot uint64; name string; addend int64; weak bool; self int64 }{%s}\n", goList(d.Binds, func(b translate.DylibBind) string {
		self := int64(-1)
		if off, ok := exports[b.Name]; ok && b.Library == "" {
			self = int64(off)
		}
		return fmt.Sprintf("{%#x,%q,%d,%t,%d}", b.Slot, b.Name, b.Addend, b.Weak, self)
	}))
	var descriptors []uint64
	if d.TLV != nil {
		descriptors = d.TLV.Descriptors
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
// dylibLoad maps the dylib into private memory and binds it as dyld would.
func dylibLoad() {
	const size, arm64 = %#x, %t
	libc, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil { panic(err) }
	var mmap func(uintptr, uintptr, int32, int32, int32, int64) uintptr
	var mprotect func(uintptr, uintptr, int32) int32
	var registerFrame func(uintptr)
	purego.RegisterLibFunc(&mmap, libc, "mmap")
	purego.RegisterLibFunc(&mprotect, libc, "mprotect")
	purego.RegisterLibFunc(&registerFrame, libc, "__register_frame")
	const read, write, exec = 1, 2, 4
	const private, fixed, anonymous, jit = 0x2, 0x10, 0x1000, 0x800
	flags, prot := int32(private|anonymous), int32(read|write)
	if arm64 { flags, prot = flags|jit, read|write|exec }
	base := mmap(0, size, prot, flags, -1, 0)
	if base == ^uintptr(0) { panic("bao: dylib image allocation failed") }
	var writeProtect func(int32)
	if arm64 {
		purego.RegisterLibFunc(&writeProtect, libc, "pthread_jit_write_protect_np")
		for _, s := range dylibSegments {
			if s.prot&exec == 0 && mmap(base+uintptr(s.start), uintptr(s.end-s.start), read|write, private|anonymous|fixed, -1, 0) != base+uintptr(s.start) { panic("bao: dylib data mapping failed") }
		}
		writeProtect(0)
	}
	image := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	copy(image, dylibImage)
	if arm64 { writeProtect(1) }
	word := func(off uint64) *uint64 { return (*uint64)(unsafe.Pointer(&image[off])) }
	for _, r := range dylibRebases { *word(r.slot) = uint64(base) + r.target }
	for _, b := range dylibBinds {
		var address uintptr
		if b.self >= 0 {
			address = base + uintptr(b.self)
		} else if a, err := purego.Dlsym(purego.RTLD_DEFAULT, b.name); err == nil {
			address = a
		} else if !b.weak {
			panic("bao: dylib import " + b.name + " is unavailable")
		}
		if address != 0 { address = uintptr(int64(address) + b.addend) }
		*word(b.slot) = uint64(address)
	}
	for _, d := range dylibTLVDescriptors { *word(d), *word(d + 8) = uint64(tlsAddress_thunk()), 0 }
	for _, s := range dylibSegments {
		if arm64 && s.prot&exec != 0 { continue }
		if mprotect(base+uintptr(s.start), uintptr(s.end-s.start), s.prot) != 0 { panic("bao: dylib page protection failed") }
	}
	if arm64 {
		var invalidate func(uintptr, uintptr)
		purego.RegisterLibFunc(&invalidate, libc, "sys_icache_invalidate")
		invalidate(base, size)
	}
	for _, f := range dylibFDEs { registerFrame(base + uintptr(f)) }
	dylibBase = base
	var callConstructor func(uintptr)
	purego.RegisterFunc(&callConstructor, nativeDylibConstructorCaller())
	for _, f := range dylibInitializers { callConstructor(base + uintptr(f)) }
}

// SharedObjectExport returns the run-time address of a dylib export.
func SharedObjectExport(name string) (uintptr, bool) {
	i := sort.SearchStrings(dylibExportNames[:], name)
	if i == len(dylibExportNames) || dylibExportNames[i] != name { return 0, false }
	return dylibBase + uintptr(dylibExportOffsets[i]), true
}

// SharedObjectExports lists the dylib's exported names, sorted.
func SharedObjectExports() []string { return append([]string(nil), dylibExportNames[:]...) }
`, d.Size, p.Arch == "arm64")
}
