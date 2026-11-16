package translate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"testing"
)

// The anchor must pass Bao's ordinary pipeline and leave the image as one
// 16 KiB-aligned, non-executable ELF section starting at its base symbol: Go's
// Darwin linker then places it in the signed __TEXT segment.
func TestDylibAnchorCarriesImage(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		img := make([]byte, 0x8000)
		copy(img, "image!")
		d := &DylibImage{SHA256: "0123456789abcdef0123", Image: img}
		p, err := LowerTLSKeeping(dylibAnchor(arch, d), nil)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		b, err := ELFContainer(p.Objects[0])
		if err != nil {
			t.Fatal(err)
		}
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		syms, err := f.Symbols()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, sym := range syms {
			if sym.Name != d.BaseSymbol() {
				continue
			}
			s := f.Sections[sym.Section]
			data, _ := s.Data()
			found = s.Addralign == 16384 && s.Flags&elf.SHF_ALLOC != 0 && s.Flags&(elf.SHF_EXECINSTR|elf.SHF_WRITE) == 0 && sym.Value == 0 && bytes.HasPrefix(data, []byte("image!"))
		}
		if !found {
			t.Fatalf("%s: image section or base symbol missing", arch)
		}
	}
}

func TestArm64CompactCFI(t *testing.T) {
	// FRAME with x19/x20 and d8/d9: CFA = FP+16, FP/LR, then the pairs below.
	got, err := arm64CompactCFI(0x04000101)
	want := []byte{0x0c, 29, 16, 0x9d, 2, 0x9e, 1, 0x80 + 19, 3, 0x80 + 20, 4, 5, 72, 5, 5, 73, 6}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("frame: % x %v", got, err)
	}
	// FRAMELESS with a 48-byte stack and x19/x20 saved.
	got, err = arm64CompactCFI(0x02003001)
	want = []byte{0x0e, 48, 0x80 + 19, 1, 0x80 + 20, 2}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("frameless: % x %v", got, err)
	}
	if _, err := arm64CompactCFI(0x02000001); err == nil {
		t.Fatal("a frameless stack too small for its pairs was accepted")
	}
}

// encodePermutation is ld64's encoder for frameless register permutations.
func encodePermutation(regs []int) uint32 {
	n := len(regs)
	renumbered := make([]int, n)
	for i := range regs {
		count := 0
		for j := 0; j < i; j++ {
			if regs[j] < regs[i] {
				count++
			}
		}
		renumbered[i] = regs[i] - count - 1
	}
	switch n {
	case 6:
		return uint32(120*renumbered[0] + 24*renumbered[1] + 6*renumbered[2] + 2*renumbered[3] + renumbered[4])
	case 5:
		return uint32(120*renumbered[0] + 24*renumbered[1] + 6*renumbered[2] + 2*renumbered[3] + renumbered[4])
	case 4:
		return uint32(60*renumbered[0] + 12*renumbered[1] + 3*renumbered[2] + renumbered[3])
	case 3:
		return uint32(20*renumbered[0] + 4*renumbered[1] + renumbered[2])
	case 2:
		return uint32(5*renumbered[0] + renumbered[1])
	case 1:
		return uint32(renumbered[0])
	}
	return 0
}

func TestAMD64CompactCFIPermutations(t *testing.T) {
	dwarf := []byte{0, 3, 12, 13, 14, 15, 6}
	for _, regs := range [][]int{{1}, {6, 1}, {2, 4, 1}, {5, 3, 6, 1}, {1, 2, 3, 4, 5}, {6, 5, 4, 3, 2, 1}} {
		enc := 0x02000000 | 5<<16 | uint32(len(regs))<<10 | encodePermutation(regs)
		got, err := amd64CompactCFI(enc, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0x0e, 40}
		for i, r := range regs {
			want = append(want, 0x80+dwarf[r], byte(1+len(regs)-i))
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%v: % x, want % x", regs, got, want)
		}
	}
	// STACK_IND reads the SUB immediate at the function's offset.
	img := make([]byte, 16)
	binary.LittleEndian.PutUint32(img[4+7:], 0x1000)
	got, err := amd64CompactCFI(0x03000000|7<<16|1<<13, img, 4)
	if err != nil || !bytes.Equal(got, append([]byte{0x0e}, appendULEB(nil, 0x1008)...)) {
		t.Fatalf("stack_ind: % x %v", got, err)
	}
}

func TestExportTrie(t *testing.T) {
	// root: no export, one edge "_" -> node1; node1: edges "a" -> A, "bc" -> B
	trie := []byte{0, 1, '_', 0, 5}
	node1 := len(trie)
	trie[4] = byte(node1)
	trie = append(trie, 0, 2, 'a', 0, 0, 'b', 'c', 0, 0)
	a := len(trie)
	trie[node1+4] = byte(a)
	trie = append(trie, 2, 0, 0x10, 0)
	b := len(trie)
	trie[node1+8] = byte(b)
	trie = append(trie, 3, 0, 0x80, 0x01, 0)
	d := &DylibImage{Segments: []DylibSegment{{"__TEXT", 0, 0x1000, 5}}}
	segmentAt := func(off uint64) *DylibSegment {
		if off < 0x1000 {
			return &d.Segments[0]
		}
		return nil
	}
	if err := d.exportTrie(trie, segmentAt); err != nil {
		t.Fatal(err)
	}
	if len(d.Exports) != 2 {
		t.Fatalf("exports %+v", d.Exports)
	}
	got := map[string]uint64{}
	for _, e := range d.Exports {
		got[e.Name] = e.Offset
	}
	if got["a"] != 0x10 || got["bc"] != 0x80 {
		t.Fatalf("exports %+v", d.Exports)
	}
}

// An attached object's references to the dylib's exports become definitions
// in the image section, a selected dylib export gets a global name, and a
// wrapped bind names the object's __wrap_ definition.
func TestAttachDylib(t *testing.T) {
	glue := machoObject(macho.CpuArm64, []anchorSection{
		{seg: "__TEXT", name: "__text", flags: 0x80000400, data: []byte{0xc0, 0x03, 0x5f, 0xd6}, align: 2},
		{seg: "__DATA", name: "__data", data: make([]byte, 8), align: 3, relocs: []anchorReloc{{0, 2}}},
	}, []anchorSymbol{
		{name: "_glue", section: 1, global: true},
		{name: "___wrap_pthread_create", section: 1, global: true},
		{name: "_PyFoo"},
	})
	newImage := func() *DylibImage {
		return &DylibImage{Arch: "arm64", SHA256: "0123456789abcdef0123", Image: make([]byte, 0x8000),
			Exports: []DylibExport{{"PyBar", 0x200, true}, {"PyFoo", 0x100, true}},
			Binds:   []DylibBind{{Slot: 0x10, Name: "pthread_create", Library: "/usr/lib/libSystem.B.dylib"}, {Slot: 0x18, Name: "malloc", Library: "/usr/lib/libSystem.B.dylib"}}}
	}
	d := newImage()
	o, err := d.attach(Object{Name: "glue.o", Data: glue}, []string{"glue", "PyBar"}, []string{"pthread_create"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Attached || d.Binds[0].Wrap != "__wrap_pthread_create" || d.Binds[1].Wrap != "" {
		t.Fatalf("binds: %+v", d.Binds)
	}
	p, err := LowerTLSKeeping(o, []string{"glue", "PyBar", "__wrap_pthread_create"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ELFContainer(p.Objects[0])
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	image := -1
	byName := map[string]elf.Symbol{}
	for _, s := range syms {
		byName[s.Name] = s
		if s.Name == d.BaseSymbol() {
			image = int(s.Section)
			if f.Sections[image].Addralign != 16384 || s.Value != 0 {
				t.Fatalf("image section: %+v", f.Sections[image])
			}
		}
	}
	if image < 0 {
		t.Fatal("no image base symbol")
	}
	if s := byName["PyBar"]; int(s.Section) != image || s.Value != 0x200 || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
		t.Fatalf("selected dylib export: %+v", s)
	}
	if s, ok := byName["__wrap_pthread_create"]; !ok || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
		t.Fatal("wrap target lost its global name")
	}
	// The data word's relocation targets PyFoo's image offset.
	found := false
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		data, _ := s.Data()
		for at := 0; at+24 <= len(data); at += 24 {
			sym := syms[binary.LittleEndian.Uint64(data[at+8:])>>32-1]
			found = found || int(sym.Section) == image && sym.Value+binary.LittleEndian.Uint64(data[at+16:]) == 0x100
		}
	}
	if !found {
		t.Fatal("no data relocation to PyFoo's image offset")
	}
	if _, ok := byName["PyFoo"]; ok {
		t.Fatal("a referenced dylib export became a global symbol")
	}
	if _, err := newImage().attach(Object{Name: "glue.o", Data: glue}, nil, []string{"malloc"}); err == nil {
		t.Fatal("wrapping a bind without a __wrap_ definition was accepted")
	}
	if _, err := newImage().attach(Object{Name: "glue.o", Data: glue}, []string{"PyBaz"}, nil); err == nil {
		t.Fatal("a selected name neither the object nor the dylib defines was accepted")
	}
}
