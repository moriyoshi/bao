package symedit

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// COFF constants from the PE/COFF specification.
const (
	coffFileHeader    = 20
	coffSectionHeader = 40
	coffSymbolSize    = 18
	coffRelocSize     = 10
	// The bigobj format (cl /bigobj, GNU as -mbig-obj) has a 56-byte header
	// with 32-bit counts, 20-byte symbol and auxiliary records with 32-bit
	// section numbers, and a high half of the associative section number in
	// section definitions.
	coffBigHeader     = 56
	coffBigSymbolSize = 20

	coffMachineAMD64 = 0x8664
	coffMachineARM64 = 0xaa64

	coffClassExternal     = 2
	coffClassStatic       = 3
	coffClassWeakExternal = 105

	coffSymAbsolute        = -1
	coffSelectNoDuplicates = 1
	coffTypeFunction       = 0x20
	coffSelectAssociative  = 5
	// IMAGE_WEAK_EXTERN_SEARCH_ALIAS: the weak external is its default's
	// alias, the encoding clang uses for weak definitions and references.
	coffWeakSearchAlias = 3

	coffNrelocOvfl  = 0x01000000
	coffComdat      = 0x00001000
	coffDiscardable = 0x02000000
)

type coffSection struct {
	name           string
	flags          uint32
	reloff, nreloc uint32
	firstReloc     uint32 // 1 when the first entry holds an overflowed count
	nlines         uint16
	header         int
	contents       uint32
	size           uint32
}

// coffSymbol is a symbol record and the auxiliary records that follow it.
type coffSymbol struct {
	index     int
	name      string
	value     uint32
	section   int32
	typ       uint16
	class     byte
	naux      int
	isSection bool // the section-definition symbol of its section
	// aux replaces the auxiliary records of a rewritten symbol. A weak
	// external's tag may be 1<<31 plus the position of a symbol to number.
	aux []byte
}

func (s coffSymbol) external() bool { return s.class == coffClassExternal }
func (s coffSymbol) weakAlias(f *coffFile) bool {
	return s.class == coffClassWeakExternal && s.naux > 0 && s.index >= 0 && le.Uint32(f.aux(s)[4:]) == coffWeakSearchAlias
}
func (s coffSymbol) undefined() bool { return s.external() && s.section == 0 && s.value == 0 }
func (s coffSymbol) common() bool    { return s.external() && s.section == 0 && s.value != 0 }

// cname is the name edits match. amd64 and arm64 COFF symbols carry no C
// underscore. Section definitions, files, labels and weak externals (whose
// default definition is a separate symbol) have none.
func (s coffSymbol) cname() string {
	if s.isSection || s.class != coffClassExternal && s.class != coffClassStatic || strings.HasPrefix(s.name, "@") || strings.HasPrefix(s.name, ".") {
		return ""
	}
	return s.name
}

func (s coffSymbol) view() elfSymbol {
	bind := elf.STB_LOCAL
	if s.external() {
		bind = elf.STB_GLOBAL
	}
	shndx := uint16(1)
	if s.common() {
		shndx = uint16(elf.SHN_COMMON)
	} else if s.external() && s.section == 0 {
		shndx = uint16(elf.SHN_UNDEF)
	}
	return elfSymbol{name: s.cname(), info: elf.ST_INFO(bind, elf.STT_NOTYPE), shndx: shndx}
}

type coffFile struct {
	data     []byte
	sections []coffSection
	symbols  []coffSymbol
	records  int // symbol table records, including auxiliary ones
	symoff   uint32
	strtab   []byte // including its 4-byte size
	// imports marks the import descriptor and thunk objects of an import
	// library, which have .idata sections. Like short import members they
	// are left alone, and their names are the ones the linker looks up.
	imports bool
	// numbers maps a section's input number to its output one, or to 0 for
	// a removed section. It is nil when no section is removed.
	numbers []int
	coffLayout
}

// coffLayout locates the fields that differ between regular and bigobj
// objects.
type coffLayout struct {
	big bool
	// header is the file header's size, which section headers follow, and
	// symSize the size of a symbol or auxiliary record.
	header, symSize int
}

var bigObjClassID = []byte{0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b, 0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8}

// isBigObj reports an ANON_OBJECT_HEADER_BIGOBJ: Sig1 0, Sig2 0xffff,
// version 2 or later and the bigobj class ID.
func isBigObj(data []byte) bool {
	return len(data) >= coffBigHeader && le.Uint16(data) == 0 && le.Uint16(data[2:]) == 0xffff && le.Uint16(data[4:]) >= 2 && bytes.Equal(data[12:28], bigObjClassID)
}

func (l coffLayout) machineAt() int { return map[bool]int{false: 0, true: 6}[l.big] }
func (l coffLayout) countsAt() (sections, symoff, records int) {
	if l.big {
		return 44, 48, 52
	}
	return 2, 8, 12
}

func (l coffLayout) sectionCount(data []byte) int {
	at, _, _ := l.countsAt()
	if l.big {
		return int(le.Uint32(data[at:]))
	}
	return int(le.Uint16(data[at:]))
}

func (l coffLayout) putSectionCount(data []byte, n int) {
	at, _, _ := l.countsAt()
	if l.big {
		le.PutUint32(data[at:], uint32(n))
	} else {
		le.PutUint16(data[at:], uint16(n))
	}
}

// symbolSection reads a symbol record's section number.
func (l coffLayout) symbolSection(e []byte) int32 {
	if l.big {
		return int32(le.Uint32(e[12:]))
	}
	return int32(int16(le.Uint16(e[12:])))
}

func (l coffLayout) putSymbolSection(e []byte, v int32) {
	if l.big {
		le.PutUint32(e[12:], uint32(v))
	} else {
		le.PutUint16(e[12:], uint16(v))
	}
}

// Offsets of a symbol record's type, storage class and auxiliary count.
func (l coffLayout) typeAt() int  { return l.symSize - 4 }
func (l coffLayout) classAt() int { return l.symSize - 2 }
func (l coffLayout) nauxAt() int  { return l.symSize - 1 }

// auxNumber reads a section definition's associated section number, whose
// high half bigobj stores after the selection.
func (l coffLayout) auxNumber(aux []byte) int {
	n := int(le.Uint16(aux[12:]))
	if l.big {
		n |= int(le.Uint16(aux[16:])) << 16
	}
	return n
}

func (l coffLayout) putAuxNumber(aux []byte, n int) {
	le.PutUint16(aux[12:], uint16(n))
	if l.big {
		le.PutUint16(aux[16:], uint16(n>>16))
	}
}

func isCOFF(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch le.Uint16(data) {
	case coffMachineAMD64, coffMachineARM64, 0x14c, 0x1c4, 0xa641, 0xa64e:
		return true
	case 0:
		return le.Uint16(data[2:]) == 0xffff
	}
	return false
}

func parseCOFF(data []byte) (*coffFile, error) {
	if len(data) < coffFileHeader {
		return nil, errors.New("short COFF object")
	}
	layout := coffLayout{header: coffFileHeader, symSize: coffSymbolSize}
	if isBigObj(data) {
		layout = coffLayout{big: true, header: coffBigHeader, symSize: coffBigSymbolSize}
	}
	switch m := le.Uint16(data[layout.machineAt():]); {
	case m == coffMachineAMD64 || m == coffMachineARM64:
	case !layout.big && m == 0:
		return nil, errors.New("COFF short import members are not edited")
	default:
		return nil, fmt.Errorf("only amd64 and arm64 COFF objects are supported, not machine %#x", m)
	}
	if !layout.big && le.Uint16(data[16:]) != 0 {
		return nil, errors.New("not a COFF relocatable object")
	}
	nsect := layout.sectionCount(data)
	_, symoffAt, recordsAt := layout.countsAt()
	f := &coffFile{data: data, symoff: le.Uint32(data[symoffAt:]), records: int(le.Uint32(data[recordsAt:])), coffLayout: layout}
	if uint64(layout.header)+uint64(nsect)*coffSectionHeader > uint64(len(data)) {
		return nil, errors.New("COFF section headers are out of range")
	}
	if f.records > 0 && (uint64(f.symoff)+uint64(f.records)*uint64(f.symSize)+4 > uint64(len(data))) {
		return nil, errors.New("COFF symbol table is out of range")
	}
	if f.records > 0 {
		start := int(f.symoff) + f.records*f.symSize
		size := int(le.Uint32(data[start:]))
		if size < 4 || size > len(data)-start {
			return nil, errors.New("COFF string table is out of range")
		}
		f.strtab = data[start : start+size]
	}
	str := func(off uint32) (string, error) {
		if off < 4 || int(off) >= len(f.strtab) {
			return "", errors.New("COFF string offset is out of range")
		}
		end := bytes.IndexByte(f.strtab[off:], 0)
		if end < 0 {
			return "", errors.New("unterminated COFF string")
		}
		return string(f.strtab[off : int(off)+end]), nil
	}
	for i := 0; i < nsect; i++ {
		h := data[layout.header+i*coffSectionHeader:]
		name := strings.TrimRight(string(h[:8]), "\x00")
		if strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "//") {
			off, err := strconv.ParseUint(name[1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid COFF section name %q", name)
			}
			if name, err = str(uint32(off)); err != nil {
				return nil, err
			}
		}
		s := coffSection{name: name, size: le.Uint32(h[16:]), contents: le.Uint32(h[20:]), reloff: le.Uint32(h[24:]), nreloc: uint32(le.Uint16(h[32:])), nlines: le.Uint16(h[34:]), flags: le.Uint32(h[36:]), header: layout.header + i*coffSectionHeader}
		if s.flags&coffNrelocOvfl != 0 && s.nreloc == 0xffff {
			if int(s.reloff)+coffRelocSize > len(data) {
				return nil, errors.New("COFF relocations are out of range")
			}
			s.nreloc, s.firstReloc = le.Uint32(data[s.reloff:]), 1
		}
		if uint64(s.reloff)+uint64(s.nreloc)*coffRelocSize > uint64(len(data)) || uint64(s.contents)+uint64(s.size) > uint64(len(data)) {
			return nil, fmt.Errorf("COFF section %s is out of range", name)
		}
		f.sections = append(f.sections, s)
		f.imports = f.imports || name == ".idata" || strings.HasPrefix(name, ".idata$")
	}
	for i := 0; i < f.records; {
		e := data[int(f.symoff)+i*f.symSize:]
		s := coffSymbol{index: i, value: le.Uint32(e[8:]), section: layout.symbolSection(e), typ: le.Uint16(e[layout.typeAt():]), class: e[layout.classAt()], naux: int(e[layout.nauxAt()])}
		if le.Uint32(e) == 0 {
			name, err := str(le.Uint32(e[4:]))
			if err != nil {
				return nil, err
			}
			s.name = name
		} else {
			s.name = strings.TrimRight(string(e[:8]), "\x00")
		}
		if i+1+s.naux > f.records {
			return nil, errors.New("COFF auxiliary symbols are out of range")
		}
		s.isSection = s.class == coffClassStatic && s.naux > 0 && s.value == 0 && s.section > 0 && int(s.section) <= len(f.sections) && f.sections[s.section-1].name == s.name
		f.symbols = append(f.symbols, s)
		i += 1 + s.naux
	}
	return f, nil
}

func (f *coffFile) defined() []string {
	if f.imports {
		return nil
	}
	var out []string
	for _, s := range f.symbols {
		if name := s.cname(); name != "" && s.external() && (s.section != 0 || s.common()) {
			out = append(out, name)
		}
	}
	return out
}

func (f *coffFile) undefined() []string {
	if f.imports {
		return nil
	}
	var out []string
	for _, s := range f.symbols {
		if name := s.cname(); name != "" && s.undefined() {
			out = append(out, name)
		}
	}
	return out
}

// indexNames lists external definitions, including common symbols, as
// archivers do for COFF.
//
// A weak alias whose default is defined in a section is indexed too, as
// llvm-lib does. One whose default is absolute, a weak reference, is not:
// it would let the linker pull its member instead of the member holding a
// strong definition.
func (f *coffFile) indexNames() []string {
	var out []string
	byRecord := map[uint32]coffSymbol{}
	for _, s := range f.symbols {
		byRecord[uint32(s.index)] = s
	}
	for _, s := range f.symbols {
		if s.external() && s.section != 0 || s.common() {
			out = append(out, s.name)
		}
		if s.weakAlias(f) {
			if d, ok := byRecord[le.Uint32(f.aux(s))]; ok && d.section > 0 {
				out = append(out, s.name)
			}
		}
	}
	return out
}

// rewriteDirectives applies the edits to .drectve linker directives that
// name symbols: /INCLUDE, -exclude-symbols and /ALTERNATENAME. renamed maps
// input names to output names. An exclusion of a symbol that is no longer
// exported is dropped, as nothing can export it; an inclusion or alternate
// name of one is an error. It returns the new contents of changed sections.
func (f *coffFile) rewriteDirectives(renamed map[string]string, hidden map[string]bool) (map[int][]byte, error) {
	out := map[int][]byte{}
	name := func(n string) string {
		if to, ok := renamed[n]; ok {
			return to
		}
		return n
	}
	for i, s := range f.sections {
		if s.name != ".drectve" || f.removed(i+1) {
			continue
		}
		contents := strings.Trim(string(f.data[s.contents:s.contents+s.size]), "\x00")
		var words []string
		changed := false
		for _, word := range strings.Fields(contents) {
			trimmed := strings.TrimLeft(strings.Trim(word, "\x00\" "), "-/")
			key, value, _ := strings.Cut(trimmed, ":")
			value = strings.Trim(value, "\"")
			lead := word[:len(word)-len(strings.TrimLeft(word, "-/"))]
			switch strings.ToLower(key) {
			case "exclude-symbols":
				if hidden[value] {
					changed = true
					continue
				}
				if to := name(value); to != value {
					word, changed = lead+key+":"+to, true
				}
			case "include":
				if hidden[value] {
					return nil, fmt.Errorf("a .drectve /INCLUDE names %s, which the edits no longer export", value)
				}
				if to := name(value); to != value {
					word, changed = lead+key+":"+to, true
				}
			case "alternatename":
				a, b, _ := strings.Cut(value, "=")
				if hidden[a] || hidden[b] {
					return nil, fmt.Errorf("a .drectve /ALTERNATENAME names %s=%s, which the edits no longer export", a, b)
				}
				if to, tb := name(a), name(b); to != a || tb != b {
					word, changed = lead+key+":"+to+"="+tb, true
				}
			}
			words = append(words, word)
		}
		if changed {
			text := ""
			if len(words) > 0 {
				text = " " + strings.Join(words, " ")
			}
			out[i] = []byte(text)
		}
	}
	return out, nil
}

// relocations calls fn with the symbol index field of each relocation in
// the sections that are kept.
func (f *coffFile) relocations(out []byte, fn func(s coffSection, off int) error) error {
	for k, s := range f.sections {
		if f.removed(k + 1) {
			continue
		}
		for i := s.firstReloc; i < s.nreloc; i++ {
			if err := fn(s, int(s.reloff)+int(i)*coffRelocSize+4); err != nil {
				return err
			}
		}
	}
	return nil
}

// runtimeReference reports a section whose relocations a wrap redirects:
// neither debug data nor unwind tables, which describe the definition.
func (s coffSection) runtimeReference() bool {
	return !strings.HasPrefix(s.name, ".debug$") && !strings.HasPrefix(s.name, ".pdata") && !strings.HasPrefix(s.name, ".xdata") && s.flags&coffDiscardable == 0
}

func (f *coffFile) removed(number int) bool {
	return f.numbers != nil && number > 0 && number < len(f.numbers) && f.numbers[number] == 0
}

// aux returns the first auxiliary record of a symbol.
func (f *coffFile) aux(s coffSymbol) []byte {
	return f.data[int(f.symoff)+(s.index+1)*f.symSize:][:f.symSize]
}

// sectionNumbers applies -remove-section and -only-section. As in
// llvm-objcopy, an associative COMDAT section goes with the section it is
// associated with. It sets f.numbers when a section goes and returns how
// many do.
func (f *coffFile) sectionNumbers(e Edits) (int, error) {
	if e.RemoveSection.empty() && e.OnlySection.empty() {
		return 0, nil
	}
	drop := make([]bool, len(f.sections)+1)
	for k, s := range f.sections {
		drop[k+1] = e.RemoveSection.Match(s.name) || !e.OnlySection.empty() && !e.OnlySection.Match(s.name)
	}
	for changed := true; changed; {
		changed = false
		for _, s := range f.symbols {
			if !s.isSection || drop[s.section] || f.sections[s.section-1].flags&coffComdat == 0 {
				continue
			}
			if aux := f.aux(s); aux[14] == coffSelectAssociative {
				if to := f.auxNumber(aux); to < len(drop) && drop[to] {
					drop[s.section], changed = true, true
				}
			}
		}
	}
	numbers := make([]int, len(drop))
	next, dropped := 1, 0
	for k := 1; k < len(drop); k++ {
		if drop[k] {
			dropped++
		} else {
			numbers[k] = next
			next++
		}
	}
	if dropped > 0 {
		f.numbers = numbers
	}
	return dropped, nil
}

// addSymbols applies -add-symbol. COFF has no symbol visibility and its weak
// externals need a default definition, so hidden, protected and weak are
// rejected; function sets the function type. An undefined symbol of the
// name becomes the definition, so the object's references bind to it. It
// returns the names it defines externally.
func (f *coffFile) addSymbols(symbols *[]coffSymbol, adds []AddedSymbol) ([]string, error) {
	// Names are output names: those after renames and wraps.
	existing := map[string]int{}
	for i, s := range *symbols {
		if _, ok := existing[s.name]; !ok && s.external() {
			existing[s.name] = i
		}
	}
	var added []string
	for _, a := range adds {
		value := a.Value
		section := int32(coffSymAbsolute)
		if a.Symbol != "" {
			var globals, locals []int
			for i, t := range f.symbols {
				if t.cname() == a.Symbol && (t.section > 0 || t.section == coffSymAbsolute) {
					if t.external() {
						globals = append(globals, i)
					} else {
						locals = append(locals, i)
					}
				}
			}
			at, err := pickTarget(a.Name, a.Symbol, globals, locals)
			if err != nil {
				return nil, err
			}
			t := f.symbols[at]
			if f.removed(int(t.section)) {
				return nil, fmt.Errorf("cannot add symbol %s at %s, whose section is removed", a.Name, a.Symbol)
			}
			section, value = t.section, uint64(t.value)+a.Value
		}
		if value > 0xffffffff {
			return nil, fmt.Errorf("cannot add symbol %s: COFF symbol values have 32 bits", a.Name)
		}
		s := coffSymbol{index: -1, name: a.Name, class: coffClassExternal, section: section, value: uint32(value)}
		if a.Section != "" {
			k := 0
			for j, sec := range f.sections {
				if sec.name != a.Section || f.removed(j+1) {
					continue
				}
				if k != 0 {
					return nil, fmt.Errorf("cannot add symbol %s: more than one COFF section is named %s", a.Name, a.Section)
				}
				k = j + 1
			}
			if k == 0 {
				return nil, fmt.Errorf("cannot add symbol %s to missing COFF section %s", a.Name, a.Section)
			}
			s.section = int32(k)
		}
		switch a.Bind {
		case elf.STB_LOCAL:
			s.class = coffClassStatic
		case elf.STB_WEAK:
			return nil, fmt.Errorf("cannot add weak symbol %s: COFF weak externals need a default definition", a.Name)
		default:
			added = append(added, a.Name)
		}
		if a.Visibility != elf.STV_DEFAULT {
			return nil, fmt.Errorf("cannot add symbol %s with a visibility: COFF has none", a.Name)
		}
		if a.Type == elf.STT_FUNC {
			s.typ = coffTypeFunction
		}
		if at, ok := existing[s.name]; ok {
			old := (*symbols)[at]
			if !old.undefined() {
				return nil, fmt.Errorf("cannot add symbol %s, which is already defined", a.Name)
			}
			s.index, s.naux = old.index, old.naux
			(*symbols)[at] = s
			continue
		}
		if s.class == coffClassExternal {
			existing[s.name] = len(*symbols)
		}
		*symbols = append(*symbols, s)
	}
	return added, nil
}

// compactSections writes the section header table without the removed
// sections. Their contents and relocations stay unreferenced, so no other
// offset moves.
func (f *coffFile) compactSections(out []byte) {
	var table []byte
	for k, s := range f.sections {
		if !f.removed(k + 1) {
			table = append(table, out[s.header:s.header+coffSectionHeader]...)
		}
	}
	copy(out[f.header:], table)
	clear(out[f.header+len(table) : f.header+len(f.sections)*coffSectionHeader])
	f.putSectionCount(out, len(table)/coffSectionHeader)
}

// weaken turns each weakened symbol into a weak external, as clang encodes
// weak definitions and references, with IMAGE_WEAK_EXTERN_SEARCH_ALIAS and a
// default named .weak.NAME.default.SUFFIX. A definition is renamed to its
// default in place, so a COMDAT key stays its section's key, and a new weak
// external NAME follows the table; it returns those, by the definition's
// position. A weak reference becomes the weak external in place, with an
// absolute zero default. SUFFIX, as in LLVM, is the object's first strong
// external definition, which keeps the defaults of different objects apart;
// without one it is a digest of the object.
func weaken(data []byte, symSize int, symbols []coffSymbol, classes []byte, weakened []int) ([]coffSymbol, []byte, map[int]int) {
	if len(weakened) == 0 {
		return symbols, classes, nil
	}
	skip := map[int]bool{}
	for _, i := range weakened {
		skip[i] = true
	}
	suffix := ""
	for i, s := range symbols {
		if !skip[i] && classes[i] == coffClassExternal && s.section > 0 && s.cname() != "" {
			suffix = s.name
			break
		}
	}
	if suffix == "" {
		suffix = fmt.Sprintf("bao.%x", sha256.Sum256(data))[:20]
	}
	alias := func(tag int) []byte {
		aux := make([]byte, symSize)
		le.PutUint32(aux, 1<<31|uint32(tag))
		le.PutUint32(aux[4:], coffWeakSearchAlias)
		return aux
	}
	aliases := map[int]int{}
	for _, i := range weakened {
		s := symbols[i]
		def := ".weak." + s.name + ".default." + suffix
		weak := coffSymbol{index: -1, name: s.name, class: coffClassWeakExternal, naux: 1}
		if s.section != 0 {
			symbols[i].name = def
			weak.aux = alias(i)
			aliases[i] = len(symbols)
			symbols, classes = append(symbols, weak), append(classes, coffClassWeakExternal)
			continue
		}
		symbols, classes = append(symbols, coffSymbol{index: -1, name: def, class: coffClassExternal, section: coffSymAbsolute}), append(classes, coffClassExternal)
		weak.aux = alias(len(symbols) - 1)
		symbols[i], classes[i] = weak, coffClassWeakExternal
	}
	return symbols, classes, aliases
}

// editCOFF applies the edits to an amd64 or arm64 COFF object. Local and
// global symbols need no order in COFF, so binding changes edit the storage
// class in place; removals rebuild the table and renumber references.
func editCOFF(data []byte, e Edits) (objectResult, error) {
	f, err := parseCOFF(data)
	if err != nil {
		return objectResult{}, err
	}
	if e.empty() {
		return objectResult{data: data}, nil
	}
	if f.imports {
		var names []string
		for _, s := range f.symbols {
			if s.external() && s.section != 0 {
				names = append(names, s.name)
			}
		}
		if err := refuseImportEdits(names, "an import library descriptor defines", e); err != nil {
			return objectResult{}, err
		}
		return objectResult{data: data}, nil
	}
	if f.records == 0 {
		if e.editsSections() {
			return objectResult{}, errors.New("section edits need a COFF symbol table")
		}
		return objectResult{data: data}, nil
	}
	droppedCount, err := f.sectionNumbers(e)
	if err != nil {
		return objectResult{}, err
	}
	symbols := append([]coffSymbol{}, f.symbols...)
	n := len(symbols)
	wrapped := map[string]bool{}
	for _, name := range e.Wrap {
		wrapped[name] = true
	}
	definedAt := map[string]int{}
	existing := map[string]int{}
	for i, s := range symbols {
		if s.external() {
			if _, ok := existing[s.name]; !ok {
				existing[s.name] = i
			}
			if name := s.cname(); name != "" && s.section != 0 {
				definedAt[name] = i
			}
		}
	}
	// rename maps a name through -redefine-sym; an import's __imp_ pointer
	// follows its function.
	rename := func(name string) string {
		if to, ok := e.Rename[name]; ok {
			return to
		}
		if fn, ok := strings.CutPrefix(name, "__imp_"); ok {
			if to, ok := e.Rename[fn]; ok {
				return "__imp_" + to
			}
		}
		return name
	}
	renamed := 0
	retarget := map[uint32]int{}
	retargetAll := map[uint32]bool{}
	removed := make([]bool, n)
	// Directives follow explicit renames only; a wrapped name in a directive
	// still describes the real symbol.
	explicit := make([]bool, n)
	for i, s := range f.symbols {
		name := s.cname()
		if name == "" {
			continue
		}
		imp, isImp := strings.CutPrefix(name, "__imp_")
		to := name
		switch real, isReal := strings.CutPrefix(name, "__real_"); {
		case s.undefined() && wrapped[name]:
			to = "__wrap_" + name
		case s.undefined() && isImp && wrapped[imp]:
			to = "__imp___wrap_" + imp
		case s.external() && s.section != 0 && wrapped[name]:
			target, ok := existing["__wrap_"+name]
			if !ok {
				target = len(symbols)
				existing["__wrap_"+name] = target
				symbols = append(symbols, coffSymbol{index: -1, name: "__wrap_" + name, class: coffClassExternal})
			}
			retarget[uint32(s.index)] = target
		case s.undefined() && isReal && wrapped[real]:
			if def, ok := definedAt[real]; ok {
				retarget[uint32(s.index)], retargetAll[uint32(s.index)] = def, true
				removed[i] = true
				renamed++
				continue
			}
			to = real
		case s.undefined() && isImp && strings.HasPrefix(imp, "__real_") && wrapped[imp[7:]]:
			to = "__imp_" + imp[7:]
		default:
			to = rename(name)
			explicit[i] = true
		}
		if to != name {
			symbols[i].name = to
			renamed++
		}
	}
	out := bytes.Clone(data)
	// Relocations name record indices; map each to its symbol.
	byRecord := map[uint32]int{}
	for i, s := range f.symbols {
		byRecord[uint32(s.index)] = i
	}
	retargeted := 0
	if len(retarget) > 0 {
		err := f.relocations(out, func(s coffSection, off int) error {
			sym := le.Uint32(out[off:])
			target, ok := retarget[sym]
			if !ok || !retargetAll[sym] && !s.runtimeReference() {
				return nil
			}
			// Added symbols are numbered when the table is rebuilt; keep
			// their position in a high range until then.
			le.PutUint32(out[off:], uint32(target)|1<<31)
			retargeted++
			return nil
		})
		if err != nil {
			return objectResult{}, err
		}
	}
	if len(symbols) > n && retargeted == 0 {
		symbols = symbols[:n]
	}
	added, err := f.addSymbols(&symbols, e.AddSymbols)
	if err != nil {
		return objectResult{}, err
	}
	referenced := make([]bool, len(symbols))
	err = f.relocations(out, func(_ coffSection, off int) error {
		sym := le.Uint32(out[off:])
		if sym&(1<<31) != 0 {
			referenced[sym&^(1<<31)] = true
			return nil
		}
		i, ok := byRecord[sym]
		if !ok {
			return fmt.Errorf("COFF relocation names record %d, which is not a symbol", sym)
		}
		referenced[i] = true
		return nil
	})
	if err != nil {
		return objectResult{}, err
	}
	// A COMDAT section's key is the first symbol after its section
	// definition; a weak external's default is named by its tag.
	// linkOnce marks COMDAT keys whose selection already merges copies.
	linkOnce := make([]bool, n)
	for i, s := range f.symbols {
		if s.isSection && s.section > 0 && !f.removed(int(s.section)) && f.sections[s.section-1].flags&coffComdat != 0 {
			for j := i + 1; j < n; j++ {
				if f.symbols[j].section == s.section && !f.symbols[j].isSection {
					referenced[j], linkOnce[j] = true, f.aux(s)[14] != coffSelectNoDuplicates
					break
				}
			}
		}
		if s.class == coffClassWeakExternal && s.naux > 0 {
			tag := le.Uint32(f.aux(s))
			if j, ok := byRecord[tag]; ok {
				referenced[j] = true
			}
		}
	}
	rebound, removedCount := 0, 0
	var hidden []string
	var weakened []int
	classes := make([]byte, len(symbols))
	for i := range symbols {
		classes[i] = symbols[i].class
	}
	for i, s := range f.symbols {
		if removed[i] {
			continue
		}
		if symbols[i].section != s.section {
			continue // -add-symbol defined it
		}
		name := s.cname()
		v := s.view()
		bind := e.binding(v)
		local := bind == elf.STB_LOCAL
		switch {
		case f.removed(int(s.section)):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("cannot remove COFF section %s: a kept relocation, COMDAT section or weak external names %s, defined in it", f.sections[s.section-1].name, s.name)
			}
			removed[i] = true
		case name != "" && e.Strip.Match(name):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("not stripping symbol %s because a relocation, COMDAT section or weak external names it", name)
			}
			removed[i] = true
		case e.StripUnneeded && !referenced[i] && name != "" && !s.common() && (local || s.undefined()):
			removed[i] = true
		}
		switch {
		case removed[i]:
			removedCount++
		case bind == elf.STB_WEAK && elf.ST_BIND(v.info) != elf.STB_WEAK:
			// A COMDAT key whose selection merges copies is already
			// link-once.
			if linkOnce[i] {
				break
			}
			// A definition keeps its record, auxiliary ones included, such
			// as the function definition record GNU as writes; a reference's
			// record becomes the weak external.
			if s.common() || s.naux > 0 && s.section == 0 {
				return objectResult{}, fmt.Errorf("cannot weaken COFF symbol %s, which is common or an undefined symbol with auxiliary records", name)
			}
			weakened = append(weakened, i)
			rebound++
		case bind != elf.ST_BIND(v.info):
			classes[i] = coffClassExternal
			if local {
				classes[i] = coffClassStatic
			}
			rebound++
		}
		if name != "" && s.external() && s.section != 0 && (removed[i] || local) {
			hidden = append(hidden, symbols[i].name)
		}
	}
	edited := renamed + retargeted + rebound + removedCount + droppedCount + len(e.AddSymbols)
	if edited == 0 {
		return objectResult{data: data}, nil
	}
	var aliases map[int]int
	symbols, classes, aliases = weaken(data, f.symSize, symbols, classes, weakened)
	if len(aliases) > 0 {
		// Code refers to a weakened definition through its weak external,
		// so a strong definition elsewhere wins here too. Unwind and debug
		// data keep describing this definition, as for a wrap.
		err := f.relocations(out, func(s coffSection, off int) error {
			sym := le.Uint32(out[off:])
			if i, ok := byRecord[sym]; ok && sym&(1<<31) == 0 && s.runtimeReference() {
				if alias, ok := aliases[i]; ok {
					le.PutUint32(out[off:], uint32(alias)|1<<31)
				}
			}
			return nil
		})
		if err != nil {
			return objectResult{}, err
		}
	}
	renames, gone := map[string]string{}, map[string]bool{}
	for i, s := range f.symbols {
		switch {
		case removed[i] || s.external() && classes[i] == coffClassStatic:
			gone[s.name] = true
		case explicit[i] && symbols[i].name != s.name:
			if _, ok := renames[s.name]; !ok {
				renames[s.name] = symbols[i].name
			}
		}
	}
	directives, err := f.rewriteDirectives(renames, gone)
	if err != nil {
		return objectResult{}, err
	}
	for i, contents := range directives {
		h := f.sections[i].header
		le.PutUint32(out[h+16:], uint32(len(contents)))
		le.PutUint32(out[h+20:], uint32(len(out)))
		out = append(out, contents...)
	}
	if err := f.rewrite(&out, symbols, classes, removed, byRecord, directives); err != nil {
		return objectResult{}, err
	}
	if f.numbers != nil {
		f.compactSections(out)
	}
	return objectResult{data: out, edited: edited, hidden: hidden, added: added}, nil
}

// rewrite places a new symbol and string table at the end of out and
// renumbers relocations, weak external tags and .llvm_addrsig entries.
func (f *coffFile) rewrite(out *[]byte, symbols []coffSymbol, classes []byte, removed []bool, byRecord map[uint32]int, resized map[int][]byte) error {
	n := len(f.symbols)
	index := make([]uint32, len(symbols))
	next := uint32(0)
	for i, s := range symbols {
		index[i] = removedIndex
		if i < n && removed[i] {
			continue
		}
		index[i] = next
		next += 1 + uint32(s.naux)
	}
	renumber := func(sym uint32) (uint32, error) {
		i, ok := int(sym&^(1<<31)), true
		if sym&(1<<31) == 0 {
			i, ok = byRecord[sym]
		}
		if !ok || index[i] == removedIndex {
			return 0, fmt.Errorf("COFF reference to removed symbol record %d", sym)
		}
		return index[i], nil
	}
	if next != uint32(f.records) || len(symbols) != n {
		for _, s := range f.sections {
			if s.nlines != 0 {
				return errors.New("COFF line numbers refer to symbol indices that cannot be renumbered")
			}
		}
	}
	err := f.relocations(*out, func(_ coffSection, off int) error {
		sym, err := renumber(le.Uint32((*out)[off:]))
		if err == nil {
			le.PutUint32((*out)[off:], sym)
		}
		return err
	})
	if err != nil {
		return err
	}
	strtab := bytes.Clone(f.strtab)
	if len(strtab) == 0 {
		strtab = []byte{4, 0, 0, 0}
	}
	offsets := map[string]uint32{}
	size := f.symSize
	table := make([]byte, 0, int(next)*size)
	for i, s := range symbols {
		if index[i] == removedIndex {
			continue
		}
		entry := make([]byte, size*(1+s.naux))
		if s.index >= 0 {
			copy(entry, f.data[int(f.symoff)+s.index*size:])
		}
		section := s.section
		if f.numbers != nil && section > 0 {
			section = int32(f.numbers[section])
		}
		le.PutUint32(entry[8:], s.value)
		f.putSymbolSection(entry, section)
		le.PutUint16(entry[f.typeAt():], s.typ)
		// An associative COMDAT section names the section it follows.
		if s.isSection && f.numbers != nil && entry[size+14] == coffSelectAssociative {
			if to := f.auxNumber(entry[size:]); to < len(f.numbers) {
				f.putAuxNumber(entry[size:], f.numbers[to])
			}
		}
		if s.index < 0 || s.name != f.symbols[i].name {
			for j := 0; j < 8; j++ {
				entry[j] = 0
			}
			if len(s.name) <= 8 {
				copy(entry, s.name)
			} else {
				off, ok := offsets[s.name]
				if !ok {
					if uint64(len(strtab))+uint64(len(s.name)) >= 1<<32 {
						return errors.New("COFF string table is too large")
					}
					off = uint32(len(strtab))
					strtab = append(append(strtab, s.name...), 0)
					offsets[s.name] = off
				}
				le.PutUint32(entry[4:], off)
			}
		}
		entry[f.classAt()] = classes[i]
		if s.aux != nil {
			copy(entry[size:], s.aux)
			entry[f.nauxAt()] = byte(s.naux)
		}
		// A section definition records its section's length.
		if contents, ok := resized[int(s.section)-1]; ok && s.isSection {
			le.PutUint32(entry[size:], uint32(len(contents)))
		}
		if s.class == coffClassWeakExternal && s.naux > 0 {
			tag, err := renumber(le.Uint32(entry[size:]))
			if err != nil {
				return err
			}
			le.PutUint32(entry[size:], tag)
		}
		table = append(table, entry...)
	}
	le.PutUint32(strtab, uint32(len(strtab)))
	// LLVM's address-significance table lists symbol indices as ULEB128.
	for k, s := range f.sections {
		if s.name != ".llvm_addrsig" || s.size == 0 || f.removed(k+1) {
			continue
		}
		var list []byte
		for data := f.data[s.contents : s.contents+s.size]; len(data) > 0; {
			v, k := binary.Uvarint(data)
			if k <= 0 {
				return errors.New("malformed LLVM address-significance table")
			}
			data = data[k:]
			if i, ok := byRecord[uint32(v)]; ok && removed[i] {
				continue
			}
			sym, err := renumber(uint32(v))
			if err != nil {
				return err
			}
			list = binary.AppendUvarint(list, uint64(sym))
		}
		for len(*out)%4 != 0 {
			*out = append(*out, 0)
		}
		le.PutUint32((*out)[s.header+16:], uint32(len(list)))
		le.PutUint32((*out)[s.header+20:], uint32(len(*out)))
		*out = append(*out, list...)
	}
	if uint64(len(*out))+uint64(len(table))+uint64(len(strtab)) >= 1<<32 {
		return errors.New("COFF object is too large")
	}
	_, symoffAt, recordsAt := f.countsAt()
	le.PutUint32((*out)[symoffAt:], uint32(len(*out)))
	le.PutUint32((*out)[recordsAt:], next)
	*out = append(append(*out, table...), strtab...)
	return nil
}
