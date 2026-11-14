package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

type testSymbol struct {
	name  string
	bind  elf.SymBind
	typ   elf.SymType
	shndx elf.SectionIndex
}

// Section indices of testObject.
const (
	textSection  = 1
	relaText     = 2
	debugSection = 3
	relaDebug    = 4
	symtabIndex  = 5
	shndxIndex   = 6
	strtabIndex  = 7
)

// testObject builds an aarch64 relocatable object. Its string table also holds
// the section names, as LLVM emits. .rela.text references each symbol in order,
// and .rela.debug_info references the symbol named debugRef.
func testObject(symbols []testSymbol, debugRef string) []byte {
	strtab := []byte{0}
	intern := func(s string) uint32 {
		if s == "" {
			return 0
		}
		if i := bytes.Index(strtab, append([]byte(s), 0)); i > 0 && strtab[i-1] == 0 {
			return uint32(i)
		}
		off := uint32(len(strtab))
		strtab = append(append(strtab, s...), 0)
		return off
	}
	names := []string{"", ".text", ".rela.text", ".debug_info", ".rela.debug_info", ".symtab", ".symtab_shndx", ".strtab"}
	nameOffsets := make([]uint32, len(names))
	for i, n := range names {
		nameOffsets[i] = intern(n)
	}
	all := append([]testSymbol{{}}, symbols...)
	var symtab []byte
	locals := 0
	for i, s := range all {
		e := make([]byte, symbolSize)
		binary.LittleEndian.PutUint32(e, intern(s.name))
		e[4] = elf.ST_INFO(s.bind, s.typ)
		binary.LittleEndian.PutUint16(e[6:], uint16(s.shndx))
		symtab = append(symtab, e...)
		if s.bind == elf.STB_LOCAL {
			locals = i + 1
		}
	}
	rela := func(sym int) []byte {
		e := make([]byte, 24)
		binary.LittleEndian.PutUint64(e[8:], uint64(sym)<<32|uint64(elf.R_AARCH64_CALL26))
		return e
	}
	var relaTextData, relaDebugData []byte
	for i, s := range symbols {
		relaTextData = append(relaTextData, rela(i+1)...)
		if s.name == debugRef {
			relaDebugData = append(relaDebugData, rela(i+1)...)
		}
	}
	type sec struct {
		typ        elf.SectionType
		flags      elf.SectionFlag
		data       []byte
		link, info uint32
		align      uint64
		entsize    uint64
	}
	sections := []sec{
		{},
		{elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_EXECINSTR, make([]byte, 16), 0, 0, 4, 0},
		{elf.SHT_RELA, elf.SHF_INFO_LINK, relaTextData, symtabIndex, textSection, 8, 24},
		{elf.SHT_PROGBITS, 0, make([]byte, 8), 0, 0, 1, 0},
		{elf.SHT_RELA, elf.SHF_INFO_LINK, relaDebugData, symtabIndex, debugSection, 8, 24},
		{elf.SHT_SYMTAB, 0, symtab, strtabIndex, uint32(locals), 8, symbolSize},
		{elf.SHT_SYMTAB_SHNDX, 0, make([]byte, 4*len(all)), symtabIndex, 0, 4, 4},
		{elf.SHT_STRTAB, 0, nil, 0, 0, 1, 0},
	}
	sections[strtabIndex].data = strtab
	out := make([]byte, 64)
	headers := make([]byte, 0, len(sections)*sectionHeaderSize)
	for i, s := range sections {
		for s.align > 1 && uint64(len(out))%s.align != 0 {
			out = append(out, 0)
		}
		h := make([]byte, sectionHeaderSize)
		if i > 0 {
			binary.LittleEndian.PutUint32(h, nameOffsets[i])
			binary.LittleEndian.PutUint32(h[4:], uint32(s.typ))
			binary.LittleEndian.PutUint64(h[8:], uint64(s.flags))
			binary.LittleEndian.PutUint64(h[24:], uint64(len(out)))
			binary.LittleEndian.PutUint64(h[32:], uint64(len(s.data)))
			binary.LittleEndian.PutUint32(h[40:], s.link)
			binary.LittleEndian.PutUint32(h[44:], s.info)
			binary.LittleEndian.PutUint64(h[48:], s.align)
			binary.LittleEndian.PutUint64(h[56:], s.entsize)
			out = append(out, s.data...)
		}
		headers = append(headers, h...)
	}
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	shoff := len(out)
	out = append(out, headers...)
	copy(out, elf.ELFMAG)
	out[elf.EI_CLASS], out[elf.EI_DATA], out[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(out[16:], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(out[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(out[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(out[0x28:], uint64(shoff))
	binary.LittleEndian.PutUint16(out[0x34:], 64)
	binary.LittleEndian.PutUint16(out[0x3a:], sectionHeaderSize)
	binary.LittleEndian.PutUint16(out[0x3c:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(out[0x3e:], strtabIndex)
	return out
}

func fixture() []byte {
	return testObject([]testSymbol{
		{".text", elf.STB_LOCAL, elf.STT_SECTION, textSection},
		{"helper", elf.STB_LOCAL, elf.STT_FUNC, textSection},
		{"foo", elf.STB_GLOBAL, elf.STT_FUNC, textSection},
		{"bar", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF},
		{"__real_foo", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF},
		{"baz", elf.STB_WEAK, elf.STT_NOTYPE, elf.SHN_UNDEF},
		{"shared", elf.STB_GLOBAL, elf.STT_OBJECT, elf.SHN_COMMON},
	}, "foo")
}

// view reads an object back with the standard library: its symbol names, the
// symbol each relocation of a section references, and its section headers.
func view(t *testing.T, data []byte) (*elf.File, []string, map[string][]string) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, s := range symbols {
		names = append(names, s.Name)
	}
	relocs := map[string][]string{}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		b, err := s.Data()
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < len(b); off += 24 {
			sym := binary.LittleEndian.Uint64(b[off+8:]) >> 32
			relocs[s.Name] = append(relocs[s.Name], names[sym-1])
		}
	}
	return f, names, relocs
}

func TestWrapAndRename(t *testing.T) {
	in := fixture()
	original := bytes.Clone(in)
	out, n, err := Edit(in, Edits{Wrap: []string{"foo", "bar"}, Rename: map[string]string{"baz": "qux", "helper": "helper2", ".text": "ignored"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, original) {
		t.Fatal("input was modified")
	}
	f, names, relocs := view(t, out)
	// __real_foo binds to foo; the reference from foo's own object is wrapped
	// through a new undefined function symbol, but debug data keeps foo.
	wantNames := []string{".text", "helper2", "foo", "__wrap_bar", "foo", "qux", "shared", "__wrap_foo"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("symbols = %q, want %q", names, wantNames)
	}
	if want := []string{".text", "helper2", "__wrap_foo", "__wrap_bar", "foo", "qux", "shared"}; !reflect.DeepEqual(relocs[".rela.text"], want) {
		t.Fatalf(".rela.text = %q, want %q", relocs[".rela.text"], want)
	}
	if want := []string{"foo"}; !reflect.DeepEqual(relocs[".rela.debug_info"], want) {
		t.Fatalf(".rela.debug_info = %q, want %q", relocs[".rela.debug_info"], want)
	}
	// Four symbol entries are renamed and one relocation is redirected.
	if n != 5 {
		t.Fatalf("edited %d, want 5", n)
	}
	symbols, _ := f.Symbols()
	added := symbols[len(symbols)-1]
	if added.Section != elf.SHN_UNDEF || elf.ST_BIND(added.Info) != elf.STB_GLOBAL || elf.ST_TYPE(added.Info) != elf.STT_FUNC {
		t.Fatalf("added symbol = %+v", added)
	}
	if s := f.Sections[shndxIndex]; s.Size != uint64(4*(len(symbols)+1)) {
		t.Fatalf("extended index size %d for %d symbols", s.Size, len(symbols)+1)
	}
	// Section names share the string table and must survive its relocation.
	for i, want := range []string{".text", ".rela.text", ".debug_info", ".rela.debug_info", ".symtab", ".symtab_shndx", ".strtab"} {
		if got := f.Sections[i+1].Name; got != want {
			t.Fatalf("section %d = %q, want %q", i+1, got, want)
		}
	}
	// Code and the unaffected relocation section bytes are unchanged.
	for _, i := range []int{textSection, debugSection, relaDebug} {
		a, _ := f.Sections[i].Data()
		g, _ := elf.NewFile(bytes.NewReader(in))
		b, _ := g.Sections[i].Data()
		if !bytes.Equal(a, b) {
			t.Fatalf("section %d changed", i)
		}
	}
}

func TestRenameInPlaceKeepsLayout(t *testing.T) {
	in := fixture()
	out, n, err := Edit(in, Edits{Rename: map[string]string{"bar": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("edited %d, want 1", n)
	}
	f, names, _ := view(t, out)
	if names[3] != "b" {
		t.Fatalf("symbols = %q", names)
	}
	g, _ := elf.NewFile(bytes.NewReader(in))
	if f.Sections[symtabIndex].Offset != g.Sections[symtabIndex].Offset {
		t.Fatal("symbol table moved without new symbols")
	}
}

func TestNoMatchReturnsInput(t *testing.T) {
	in := fixture()
	out, n, err := Edit(in, Edits{Wrap: []string{"absent"}, Rename: map[string]string{"also_absent": "x"}})
	if err != nil || n != 0 || &out[0] != &in[0] {
		t.Fatalf("Edit = %d, %v; want the input unchanged", n, err)
	}
}

func TestWrapReusesDefinedWrapper(t *testing.T) {
	in := testObject([]testSymbol{
		{"foo", elf.STB_GLOBAL, elf.STT_FUNC, textSection},
		{"__wrap_foo", elf.STB_GLOBAL, elf.STT_FUNC, textSection},
	}, "")
	out, n, err := Edit(in, Edits{Wrap: []string{"foo"}})
	if err != nil {
		t.Fatal(err)
	}
	_, names, relocs := view(t, out)
	if n != 1 || len(names) != 2 || !reflect.DeepEqual(relocs[".rela.text"], []string{"__wrap_foo", "__wrap_foo"}) {
		t.Fatalf("n=%d symbols=%q relocs=%q", n, names, relocs[".rela.text"])
	}
}

func TestDefinedAndPrefix(t *testing.T) {
	in := fixture()
	defined, err := Defined(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"foo", "shared"}; !reflect.DeepEqual(defined, want) {
		t.Fatalf("Defined = %q, want %q", defined, want)
	}
	out, _, err := Edit(in, Edits{Rename: Prefix(defined, "p_")})
	if err != nil {
		t.Fatal(err)
	}
	_, names, _ := view(t, out)
	if want := []string{".text", "helper", "p_foo", "bar", "__real_foo", "baz", "p_shared"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("symbols = %q, want %q", names, want)
	}
}

// testArchive writes a GNU archive without a symbol index.
func testArchive(members ...ar.Member) []byte {
	out := []byte("!<arch>\n")
	add := func(name string, data []byte) {
		out = fmt.Appendf(out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "644", len(data))
		out = append(out, data...)
		if len(data)%2 != 0 {
			out = append(out, '\n')
		}
	}
	var longNames []byte
	names := make([]string, len(members))
	for i, m := range members {
		names[i] = m.Name + "/"
		if len(names[i]) > 16 {
			names[i] = fmt.Sprintf("/%d", len(longNames))
			longNames = append(longNames, m.Name+"/\n"...)
		}
	}
	if len(longNames) > 0 {
		add("//", longNames)
	}
	for i, m := range members {
		add(names[i], m.Data)
	}
	return out
}

func TestArchive(t *testing.T) {
	other := testObject([]testSymbol{
		{"bar", elf.STB_GLOBAL, elf.STT_FUNC, textSection},
		{"foo", elf.STB_GLOBAL, elf.STT_NOTYPE, elf.SHN_UNDEF},
	}, "")
	long := "a-member-name-longer-than-fifteen.o"
	in := testArchive(ar.Member{Name: "one.o", Data: fixture()}, ar.Member{Name: long, Data: other})
	defined, err := Defined(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bar", "foo", "shared"}; !reflect.DeepEqual(defined, want) {
		t.Fatalf("Defined = %q, want %q", defined, want)
	}
	out, n, err := Edit(in, Edits{Rename: Prefix(defined, "p_")})
	if err != nil {
		t.Fatal(err)
	}
	// The first member's reference to bar resolves within the archive, so it
	// is prefixed with the definitions; __real_foo and baz stay imports.
	if n != 5 {
		t.Fatalf("edited %d, want 5", n)
	}
	members, err := ar.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 4 || members[0].Name != "/" || members[1].Name != "//" || members[2].Name != "one.o" || members[3].Name != long {
		t.Fatalf("members = %+v", members)
	}
	// The index names each definition with the header offset of its member.
	index := members[0].Data
	count := int(binary.BigEndian.Uint32(index))
	names := strings.Split(strings.TrimRight(string(index[4+4*count:]), "\x00"), "\x00")
	got := map[string]int{}
	for i, name := range names {
		got[name] = int(binary.BigEndian.Uint32(index[4+4*i:]))
	}
	want := map[string]int{"p_foo": members[2].Offset, "p_shared": members[2].Offset, "p_bar": members[3].Offset}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("index = %v, want %v", got, want)
	}
	_, symbols, _ := view(t, members[2].Data)
	if want := []string{".text", "helper", "p_foo", "p_bar", "__real_foo", "baz", "p_shared"}; !reflect.DeepEqual(symbols, want) {
		t.Fatalf("first member symbols = %q, want %q", symbols, want)
	}
	_, symbols, _ = view(t, members[3].Data)
	if !reflect.DeepEqual(symbols, []string{"p_bar", "p_foo"}) {
		t.Fatalf("second member symbols = %q", symbols)
	}
}

func TestArchiveRejectsOtherMembers(t *testing.T) {
	in := testArchive(ar.Member{Name: "one.o", Data: fixture()}, ar.Member{Name: "bitcode.o", Data: []byte("BC\xc0\xde")})
	if _, _, err := Edit(in, Edits{Wrap: []string{"bar"}}); err == nil || !strings.Contains(err.Error(), "bitcode.o") {
		t.Fatalf("Edit = %v, want a bitcode.o error", err)
	}
}

func TestValidateAndParseRenames(t *testing.T) {
	for _, e := range []Edits{
		{Wrap: []string{"x"}, Rename: map[string]string{"x": "y"}},
		{Wrap: []string{"x"}, Rename: map[string]string{"__real_x": "y"}},
		{Rename: map[string]string{"x": ""}},
		{Wrap: []string{""}},
	} {
		if err := e.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded", e)
		}
	}
	got, err := ParseRenames(strings.NewReader("# comment\n a  b \n\nc d # trailing\n"))
	if err != nil || !reflect.DeepEqual(got, map[string]string{"a": "b", "c": "d"}) {
		t.Fatalf("ParseRenames = %v, %v", got, err)
	}
	for _, bad := range []string{"a\n", "a b c\n", "a b\na c\n"} {
		if _, err := ParseRenames(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseRenames(%q) succeeded", bad)
		}
	}
}

func TestRejectsUnsupportedObjects(t *testing.T) {
	big := fixture()
	big[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	exec := fixture()
	binary.LittleEndian.PutUint16(exec[16:], uint16(elf.ET_EXEC))
	for _, in := range [][]byte{big, exec, []byte("not an object")} {
		if _, _, err := Edit(in, Edits{Wrap: []string{"bar"}}); err == nil {
			t.Errorf("Edit accepted %q", in[:min(len(in), 8)])
		}
	}
}
