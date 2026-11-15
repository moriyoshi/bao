package symedit

import (
	"bytes"
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

	coffMachineAMD64 = 0x8664
	coffMachineARM64 = 0xaa64

	coffClassExternal     = 2
	coffClassStatic       = 3
	coffClassWeakExternal = 105

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
	section   int16
	class     byte
	naux      int
	isSection bool // the section-definition symbol of its section
}

func (s coffSymbol) external() bool  { return s.class == coffClassExternal }
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
	switch m := le.Uint16(data); m {
	case coffMachineAMD64, coffMachineARM64:
	case 0:
		if len(data) >= 8 && le.Uint16(data[4:]) >= 2 {
			return nil, errors.New("bigobj COFF objects are unsupported")
		}
		return nil, errors.New("COFF short import members are not edited")
	default:
		return nil, fmt.Errorf("only amd64 and arm64 COFF objects are supported, not machine %#x", m)
	}
	if le.Uint16(data[16:]) != 0 {
		return nil, errors.New("not a COFF relocatable object")
	}
	nsect := int(le.Uint16(data[2:]))
	f := &coffFile{data: data, symoff: le.Uint32(data[8:]), records: int(le.Uint32(data[12:]))}
	if coffFileHeader+nsect*coffSectionHeader > len(data) {
		return nil, errors.New("COFF section headers are out of range")
	}
	if f.records > 0 && (uint64(f.symoff)+uint64(f.records)*coffSymbolSize+4 > uint64(len(data))) {
		return nil, errors.New("COFF symbol table is out of range")
	}
	if f.records > 0 {
		start := int(f.symoff) + f.records*coffSymbolSize
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
		h := data[coffFileHeader+i*coffSectionHeader:]
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
		s := coffSection{name: name, size: le.Uint32(h[16:]), contents: le.Uint32(h[20:]), reloff: le.Uint32(h[24:]), nreloc: uint32(le.Uint16(h[32:])), nlines: le.Uint16(h[34:]), flags: le.Uint32(h[36:]), header: coffFileHeader + i*coffSectionHeader}
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
	}
	for i := 0; i < f.records; {
		e := data[int(f.symoff)+i*coffSymbolSize:]
		s := coffSymbol{index: i, value: le.Uint32(e[8:]), section: int16(le.Uint16(e[12:])), class: e[16], naux: int(e[17])}
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
	var out []string
	for _, s := range f.symbols {
		if name := s.cname(); name != "" && s.external() && (s.section != 0 || s.common()) {
			out = append(out, name)
		}
	}
	return out
}

func (f *coffFile) undefined() []string {
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
func (f *coffFile) indexNames() []string {
	var out []string
	for _, s := range f.symbols {
		if s.external() && s.section != 0 || s.common() {
			out = append(out, s.name)
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
		if s.name != ".drectve" {
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

func (f *coffFile) relocations(out []byte, fn func(s coffSection, off int) error) error {
	for _, s := range f.sections {
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

// editCOFF applies the edits to an amd64 or arm64 COFF object. Local and
// global symbols need no order in COFF, so binding changes edit the storage
// class in place; removals rebuild the table and renumber references.
func editCOFF(data []byte, e Edits) (objectResult, error) {
	f, err := parseCOFF(data)
	if err != nil {
		return objectResult{}, err
	}
	if e.empty() || f.records == 0 {
		return objectResult{data: data}, nil
	}
	if !e.Weaken.empty() {
		return objectResult{}, errors.New("weakening is unsupported for COFF, whose weak externals need a default definition")
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
	for i, s := range f.symbols {
		if s.isSection && s.section > 0 && f.sections[s.section-1].flags&coffComdat != 0 {
			for j := i + 1; j < n; j++ {
				if f.symbols[j].section == s.section && !f.symbols[j].isSection {
					referenced[j] = true
					break
				}
			}
		}
		if s.class == coffClassWeakExternal && s.naux > 0 {
			tag := le.Uint32(f.data[int(f.symoff)+(s.index+1)*coffSymbolSize:])
			if j, ok := byRecord[tag]; ok {
				referenced[j] = true
			}
		}
	}
	rebound, removedCount := 0, 0
	var hidden []string
	classes := make([]byte, len(symbols))
	for i := range symbols {
		classes[i] = symbols[i].class
	}
	for i, s := range f.symbols {
		if removed[i] {
			continue
		}
		name := s.cname()
		v := s.view()
		bind := e.binding(v)
		local := bind == elf.STB_LOCAL
		switch {
		case name != "" && e.Strip.Match(name):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("not stripping symbol %s because a relocation, COMDAT section or weak external names it", name)
			}
			removed[i] = true
		case e.StripUnneeded && !referenced[i] && name != "" && !s.common() && (local || s.undefined()):
			removed[i] = true
		}
		if removed[i] {
			removedCount++
		} else if bind != elf.ST_BIND(v.info) {
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
	edited := renamed + retargeted + rebound + removedCount
	if edited == 0 {
		return objectResult{data: data}, nil
	}
	renames, gone := map[string]string{}, map[string]bool{}
	for i, s := range f.symbols {
		switch {
		case removed[i] || s.external() && classes[i] != coffClassExternal:
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
	return objectResult{data: out, edited: edited, hidden: hidden}, nil
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
	table := make([]byte, 0, int(next)*coffSymbolSize)
	for i, s := range symbols {
		if index[i] == removedIndex {
			continue
		}
		entry := make([]byte, coffSymbolSize*(1+s.naux))
		if i < n {
			copy(entry, f.data[int(f.symoff)+s.index*coffSymbolSize:])
		} else {
			entry[16] = s.class
		}
		if i >= n || s.name != f.symbols[i].name {
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
		entry[16] = classes[i]
		// A section definition records its section's length.
		if contents, ok := resized[int(s.section)-1]; ok && s.isSection {
			le.PutUint32(entry[coffSymbolSize:], uint32(len(contents)))
		}
		if s.class == coffClassWeakExternal && s.naux > 0 {
			tag, err := renumber(le.Uint32(entry[coffSymbolSize:]))
			if err != nil {
				return err
			}
			le.PutUint32(entry[coffSymbolSize:], tag)
		}
		table = append(table, entry...)
	}
	le.PutUint32(strtab, uint32(len(strtab)))
	// LLVM's address-significance table lists symbol indices as ULEB128.
	for _, s := range f.sections {
		if s.name != ".llvm_addrsig" || s.size == 0 {
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
	le.PutUint32((*out)[8:], uint32(len(*out)))
	le.PutUint32((*out)[12:], next)
	*out = append(append(*out, table...), strtab...)
	return nil
}
