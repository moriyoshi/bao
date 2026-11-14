package translate

import (
	"bytes"
	"debug/elf"
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
