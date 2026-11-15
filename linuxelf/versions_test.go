package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type testVersionedSymbol struct {
	name    string
	version int // verdef index; 1 is unversioned
	hidden  bool
}

// testVersionedLibrary writes an x86_64 shared object to root's library
// directory with the given version definitions (index 2 onward) and dynamic
// symbols, as glibc pairs a compatibility version with a default one.
func testVersionedLibrary(t *testing.T, root, name string, versions []string, symbols []testVersionedSymbol) {
	t.Helper()
	le := binary.LittleEndian
	dynstr := []byte{0}
	str := func(s string) uint32 {
		off := uint32(len(dynstr))
		dynstr = append(append(dynstr, s...), 0)
		return off
	}
	var verdef []byte
	for i, v := range append([]string{name}, versions...) {
		e := make([]byte, 28)
		le.PutUint16(e, 1)
		if i == 0 {
			le.PutUint16(e[2:], 1) // VER_FLG_BASE
		}
		le.PutUint16(e[4:], uint16(i+1))
		le.PutUint16(e[6:], 1)
		le.PutUint32(e[12:], 20)
		if i < len(versions) {
			le.PutUint32(e[16:], 28)
		}
		le.PutUint32(e[20:], str(v))
		verdef = append(verdef, e...)
	}
	dynsym := make([]byte, 24)
	versym := make([]byte, 2)
	for _, s := range symbols {
		e := make([]byte, 24)
		le.PutUint32(e, str(s.name))
		e[4] = byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC))
		le.PutUint16(e[6:], 6) // any defined section
		dynsym = append(dynsym, e...)
		v := uint16(s.version)
		if s.hidden {
			v |= 0x8000
		}
		versym = le.AppendUint16(versym, v)
	}
	shstrtab := []byte("\x00.dynstr\x00.dynsym\x00.gnu.version\x00.gnu.version_d\x00.shstrtab\x00.text\x00")
	type section struct {
		name       uint32
		typ        elf.SectionType
		data       []byte
		link, info uint32
		entsize    uint64
	}
	sections := []section{{}, {1, elf.SHT_STRTAB, dynstr, 0, 0, 0}, {9, elf.SHT_DYNSYM, dynsym, 1, 1, 24}, {17, elf.SHT_GNU_VERSYM, versym, 2, 0, 2},
		{30, elf.SHT_GNU_VERDEF, verdef, 1, uint32(len(versions) + 1), 0}, {45, elf.SHT_STRTAB, shstrtab, 0, 0, 0}, {55, elf.SHT_PROGBITS, nil, 0, 0, 0}}
	out := make([]byte, 64)
	offsets := make([]int, len(sections))
	for i, s := range sections {
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
		offsets[i] = len(out)
		out = append(out, s.data...)
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	shoff := len(out)
	for i, s := range sections {
		h := make([]byte, 64)
		le.PutUint32(h, s.name)
		le.PutUint32(h[4:], uint32(s.typ))
		le.PutUint64(h[24:], uint64(offsets[i]))
		le.PutUint64(h[32:], uint64(len(s.data)))
		le.PutUint32(h[40:], s.link)
		le.PutUint32(h[44:], s.info)
		le.PutUint64(h[56:], s.entsize)
		out = append(out, h...)
	}
	copy(out, elf.ELFMAG)
	out[elf.EI_CLASS], out[elf.EI_DATA], out[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	le.PutUint16(out[16:], uint16(elf.ET_DYN))
	le.PutUint16(out[18:], uint16(elf.EM_X86_64))
	le.PutUint32(out[20:], 1)
	le.PutUint64(out[0x28:], uint64(shoff))
	le.PutUint16(out[0x34:], 64)
	le.PutUint16(out[0x3a:], 64)
	le.PutUint16(out[0x3c:], uint16(len(sections)))
	le.PutUint16(out[0x3e:], 5)
	if _, err := elf.NewFile(bytes.NewReader(out)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "lib/x86_64-linux-gnu")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBindVersions(t *testing.T) {
	root := t.TempDir()
	// Index 2 is the x86_64 base version; 3-5 are later ones.
	testVersionedLibrary(t, root, "libc.so.6", []string{"GLIBC_2.2.5", "GLIBC_2.3.2", "GLIBC_2.14", "GLIBC_2.34"}, []testVersionedSymbol{
		{"pthread_cond_init", 2, true}, {"pthread_cond_init", 3, false},
		{"memcpy", 2, true}, {"memcpy", 4, false},
		{"dlopen", 2, true}, {"dlopen", 5, false},
		{"solo", 2, false},
		{"newest", 5, false},
		{"plain", 1, false},
	})
	imports := func() []Import {
		var out []Import
		for _, name := range []string{"pthread_cond_init", "memcpy", "dlopen", "solo", "newest", "plain"} {
			out = append(out, Import{Remote: name, Library: "libc.so.6"})
		}
		return out
	}
	versions := func(b []Import) map[string]string {
		out := map[string]string{}
		for _, i := range b {
			out[i.Remote] = i.Version
		}
		return out
	}
	for _, c := range []struct {
		caps  []string
		want  map[string]string
		above []string
	}{
		// The defaults, as a static linker records them.
		{nil, map[string]string{"pthread_cond_init": "GLIBC_2.3.2", "memcpy": "GLIBC_2.14", "dlopen": "GLIBC_2.34", "solo": "GLIBC_2.2.5", "newest": "GLIBC_2.34", "plain": ""}, nil},
		// The newest at or below the cap; unversioned when none is.
		{[]string{"GLIBC_2.17"}, map[string]string{"pthread_cond_init": "GLIBC_2.3.2", "memcpy": "GLIBC_2.14", "dlopen": "GLIBC_2.2.5", "solo": "GLIBC_2.2.5", "newest": "", "plain": ""}, []string{"newest@GLIBC_2.34"}},
		{[]string{"GLIBC_2.3"}, map[string]string{"pthread_cond_init": "GLIBC_2.2.5", "memcpy": "GLIBC_2.2.5", "dlopen": "GLIBC_2.2.5", "solo": "GLIBC_2.2.5", "newest": "", "plain": ""}, []string{"newest@GLIBC_2.34"}},
		// A cap for another namespace has no effect.
		{[]string{"GLIBCXX_3.4.19"}, map[string]string{"pthread_cond_init": "GLIBC_2.3.2", "memcpy": "GLIBC_2.14", "dlopen": "GLIBC_2.34", "solo": "GLIBC_2.2.5", "newest": "GLIBC_2.34", "plain": ""}, nil},
	} {
		caps, err := ParseMaxSymbolVersions(c.caps)
		if err != nil {
			t.Fatal(err)
		}
		b := imports()
		above, err := bindVersions(root, b, caps)
		if err != nil {
			t.Fatal(err)
		}
		if got := versions(b); !reflect.DeepEqual(got, c.want) || !reflect.DeepEqual(above, c.above) {
			t.Errorf("caps %q: versions %v above %q, want %v above %q", c.caps, got, above, c.want, c.above)
		}
	}
	for _, bad := range [][]string{{"GLIBC"}, {"GLIBC_PRIVATE"}, {"GLIBC_2.17", "GLIBC_2.28"}, {"_2.17"}} {
		if _, err := ParseMaxSymbolVersions(bad); err == nil {
			t.Errorf("ParseMaxSymbolVersions(%q) succeeded", bad)
		}
	}
	if !(symbolVersion{"GLIBC", []int{2, 3}}).less(symbolVersion{"GLIBC", []int{2, 3, 2}}) || (symbolVersion{"GLIBC", []int{2, 14}}).less(symbolVersion{"GLIBC", []int{2, 3, 4}}) {
		t.Error("release order")
	}
}
