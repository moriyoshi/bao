package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Mach-O constants from <mach-o/loader.h> and <mach-o/nlist.h>.
const (
	machoMagic64  = 0xfeedfacf
	machoHeader64 = 32
	mhObject      = 1
	lcSegment64   = 0x19
	lcSymtab      = 0x2
	lcDysymtab    = 0xb
	lcDataInCode  = 0x29
	lcLinkerHints = 0x2e
	nlistSize     = 16
	cpuARM64      = 0x0100000c

	nStab    = 0xe0
	nPext    = 0x10
	nType    = 0x0e
	nExt     = 0x01
	nUndf    = 0x0
	nSect    = 0xe
	nAbs     = 0x2
	nWeakRef = 0x40
	nWeakDef = 0x80
	// Symbols the linker must keep: no-dead-strip (from __attribute__((used)))
	// and REFERENCED_DYNAMICALLY.
	nNoDeadStrip          = 0x20
	referencedDynamically = 0x10

	sAttrDebug     = 0x02000000
	indirectLocal  = 0x80000000
	indirectAbs    = 0x40000000
	relocExtern    = 1 << 27
	relocSymbolMax = 1 << 24
	// ARM64_RELOC_ADDEND stores an addend where others store a section.
	arm64RelocAddend = 10
)

type machoSection struct {
	segname, sectname string
	addr, size        uint64
	flags             uint32
	reloff, nreloc    uint32
}

func (s machoSection) name() string { return s.segname + "," + s.sectname }

// indirect reports a section type whose entries the indirect symbol table
// lists: symbol pointers and stubs.
func (s machoSection) indirect() bool {
	switch s.flags & 0xff {
	case 0x6, 0x7, 0x8, 0x10, 0x14:
		return true
	}
	return false
}

type machoSymbol struct {
	name  string
	typ   byte
	sect  byte
	desc  uint16
	value uint64
}

func (s machoSymbol) stab() bool      { return s.typ&nStab != 0 }
func (s machoSymbol) external() bool  { return !s.stab() && s.typ&nExt != 0 }
func (s machoSymbol) undefined() bool { return s.typ&nType == nUndf }
func (s machoSymbol) common() bool    { return s.external() && s.undefined() && s.value != 0 }

// cname is the C name that edits match: the symbol name without Mach-O's
// leading underscore. Stabs, indirect and other symbols have none.
func (s machoSymbol) cname() string {
	t := s.typ & nType
	if s.stab() || t != nUndf && t != nSect && t != nAbs || len(s.name) < 2 || s.name[0] != '_' {
		return ""
	}
	return s.name[1:]
}

// view describes the symbol as the ELF binding rules see it: local, global or
// weak; hidden for a private extern; and undefined, common or defined.
func (s machoSymbol) view() elfSymbol {
	bind := elf.STB_LOCAL
	if s.external() {
		bind = elf.STB_GLOBAL
		if s.undefined() && s.desc&nWeakRef != 0 || !s.undefined() && s.desc&nWeakDef != 0 {
			bind = elf.STB_WEAK
		}
	}
	shndx := uint16(1)
	if s.common() {
		shndx = uint16(elf.SHN_COMMON)
	} else if s.undefined() {
		shndx = uint16(elf.SHN_UNDEF)
	}
	var other byte
	if s.typ&nPext != 0 {
		other = byte(elf.STV_HIDDEN)
	}
	return elfSymbol{name: s.cname(), info: elf.ST_INFO(bind, elf.STT_NOTYPE), other: other, shndx: shndx}
}

// rebind returns n_type and n_desc for a new ELF-style binding.
func (s machoSymbol) rebind(bind elf.SymBind) (byte, uint16) {
	typ, desc := s.typ, s.desc
	switch bind {
	case elf.STB_LOCAL:
		typ &^= nExt | nPext
		desc &^= nWeakDef | nWeakRef
	case elf.STB_GLOBAL:
		typ |= nExt
		desc &^= nWeakDef | nWeakRef
	case elf.STB_WEAK:
		typ |= nExt
		if s.undefined() {
			desc |= nWeakRef
		} else {
			desc |= nWeakDef
		}
	}
	return typ, desc
}

type machoFile struct {
	data     []byte
	cputype  uint32
	sections []machoSection
	// Load command offsets; each is 0 when the object has none.
	symtab, dysymtab, dataInCode, hints int
	symbols                             []machoSymbol
	// ordinals maps a section's input ordinal to its output one, or to 0
	// for a removed section. It is nil when no section is removed.
	ordinals []int
}

func isMachO(data []byte) bool {
	return len(data) >= 4 && (le.Uint32(data) == machoMagic64 || le.Uint32(data) == 0xfeedface ||
		le.Uint32(data) == 0xcefaedfe || le.Uint32(data) == 0xcffaedfe || le.Uint32(data) == 0xbebafeca)
}

func parseMachO(data []byte) (*machoFile, error) {
	if len(data) < machoHeader64 || le.Uint32(data) != machoMagic64 {
		return nil, errors.New("only 64-bit little-endian Mach-O objects are supported; split a universal file with lipo first")
	}
	if le.Uint32(data[12:]) != mhObject {
		return nil, errors.New("not a Mach-O relocatable object")
	}
	ncmds, sizeofcmds := le.Uint32(data[16:]), le.Uint32(data[20:])
	if uint64(sizeofcmds) > uint64(len(data)-machoHeader64) {
		return nil, errors.New("Mach-O load commands are out of range")
	}
	f := &machoFile{data: data, cputype: le.Uint32(data[4:])}
	off, end := machoHeader64, machoHeader64+int(sizeofcmds)
	for i := uint32(0); i < ncmds; i++ {
		if end-off < 8 {
			return nil, errors.New("Mach-O load commands are out of range")
		}
		cmd, size := le.Uint32(data[off:]), int(le.Uint32(data[off+4:]))
		if size < 8 || size > end-off {
			return nil, fmt.Errorf("Mach-O load command %d is out of range", i)
		}
		c := data[off : off+size]
		switch cmd {
		case lcSegment64:
			if size < 72 {
				return nil, errors.New("short Mach-O segment command")
			}
			n := int(le.Uint32(c[64:]))
			if n > (size-72)/80 {
				return nil, errors.New("Mach-O segment sections are out of range")
			}
			for j := 0; j < n; j++ {
				h := c[72+80*j:]
				s := machoSection{
					sectname: strings.TrimRight(string(h[:16]), "\x00"), segname: strings.TrimRight(string(h[16:32]), "\x00"),
					addr: le.Uint64(h[32:]), size: le.Uint64(h[40:]), reloff: le.Uint32(h[56:]), nreloc: le.Uint32(h[60:]), flags: le.Uint32(h[64:]),
				}
				if uint64(s.reloff)+8*uint64(s.nreloc) > uint64(len(data)) {
					return nil, fmt.Errorf("Mach-O section %s,%s relocations are out of range", s.segname, s.sectname)
				}
				f.sections = append(f.sections, s)
			}
		case lcSymtab:
			if size < 24 || f.symtab != 0 {
				return nil, errors.New("malformed or repeated Mach-O symbol table command")
			}
			f.symtab = off
		case lcDysymtab:
			if size < 80 || f.dysymtab != 0 {
				return nil, errors.New("malformed or repeated Mach-O dynamic symbol table command")
			}
			f.dysymtab = off
		case lcDataInCode, lcLinkerHints:
			if size < 16 || uint64(le.Uint32(c[8:]))+uint64(le.Uint32(c[12:])) > uint64(len(data)) {
				return nil, errors.New("malformed Mach-O linkedit data command")
			}
			if cmd == lcDataInCode {
				f.dataInCode = off
			} else {
				f.hints = off
			}
		}
		off += size
	}
	if f.symtab == 0 {
		return f, nil
	}
	symoff, nsyms := uint64(le.Uint32(data[f.symtab+8:])), uint64(le.Uint32(data[f.symtab+12:]))
	stroff, strsize := uint64(le.Uint32(data[f.symtab+16:])), uint64(le.Uint32(data[f.symtab+20:]))
	if symoff+nsyms*nlistSize > uint64(len(data)) || stroff+strsize > uint64(len(data)) {
		return nil, errors.New("Mach-O symbol table is out of range")
	}
	strtab := data[stroff : stroff+strsize]
	f.symbols = make([]machoSymbol, nsyms)
	for i := range f.symbols {
		e := data[symoff+uint64(i)*nlistSize:]
		strx := le.Uint32(e)
		name := ""
		if strx != 0 {
			if uint64(strx) >= strsize {
				return nil, fmt.Errorf("Mach-O symbol %d name is out of range", i)
			}
			end := bytes.IndexByte(strtab[strx:], 0)
			if end < 0 {
				return nil, fmt.Errorf("Mach-O symbol %d name is unterminated", i)
			}
			name = string(strtab[strx : int(strx)+end])
		}
		f.symbols[i] = machoSymbol{name: name, typ: e[4], sect: e[5], desc: le.Uint16(e[6:]), value: le.Uint64(e[8:])}
	}
	if f.dysymtab != 0 {
		d := data[f.dysymtab:]
		// Tables of contents, modules and external relocations belong to
		// linked images; their offsets would refer to the old symbol order.
		for _, field := range []int{32, 40, 48, 64, 72} {
			if le.Uint32(d[field+4:]) != 0 {
				return nil, errors.New("Mach-O object has linked-image dynamic symbol tables")
			}
		}
		indoff, nind := uint64(le.Uint32(d[56:])), uint64(le.Uint32(d[60:]))
		if indoff+4*nind > uint64(len(data)) {
			return nil, errors.New("Mach-O indirect symbol table is out of range")
		}
	}
	return f, nil
}

func (f *machoFile) defined() []string {
	var out []string
	for _, s := range f.symbols {
		if name := s.cname(); name != "" && s.external() && (!s.undefined() || s.common()) {
			out = append(out, name)
		}
	}
	return out
}

// indexNames lists external definitions by raw name without common symbols,
// as ranlib does by default.
func (f *machoFile) indexNames() []string {
	var out []string
	for _, s := range f.symbols {
		if s.external() && !s.undefined() {
			out = append(out, s.name)
		}
	}
	return out
}

func (f *machoFile) undefined() []string {
	var out []string
	for _, s := range f.symbols {
		if name := s.cname(); name != "" && s.external() && s.undefined() && !s.common() {
			out = append(out, name)
		}
	}
	return out
}

// relocations calls fn with each relocation's second word, by file offset,
// in the sections that are kept.
func (f *machoFile) relocations(out []byte, fn func(s machoSection, off int) error) error {
	for k, s := range f.sections {
		if f.ordinals != nil && f.ordinals[k+1] == 0 {
			continue
		}
		for i := uint32(0); i < s.nreloc; i++ {
			off := int(s.reloff) + 8*int(i)
			// Scattered relocations exist only in 32-bit objects.
			if le.Uint32(out[off:])&0x80000000 != 0 {
				return errors.New("scattered Mach-O relocations are unsupported")
			}
			if err := fn(s, off+4); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *machoFile) indirect(out []byte) []byte {
	if f.dysymtab == 0 {
		return nil
	}
	d := out[f.dysymtab:]
	off, n := le.Uint32(d[56:]), le.Uint32(d[60:])
	return out[off : off+4*n]
}

// sectionOrdinals applies -remove-section and -only-section, which name a
// section SEGMENT,SECTION as llvm-objcopy does. It sets f.ordinals when a
// section goes and returns how many do.
func (f *machoFile) sectionOrdinals(e Edits) (int, error) {
	if e.RemoveSection.empty() && e.OnlySection.empty() {
		return 0, nil
	}
	ordinals := make([]int, len(f.sections)+1)
	next, dropped := 1, 0
	for k, s := range f.sections {
		if e.RemoveSection.Match(s.name()) || !e.OnlySection.empty() && !e.OnlySection.Match(s.name()) {
			if s.indirect() && len(f.indirect(f.data)) > 0 {
				return 0, fmt.Errorf("cannot remove Mach-O section %s, whose entries the indirect symbol table lists", s.name())
			}
			dropped++
			continue
		}
		ordinals[k+1] = next
		next++
	}
	if dropped > 0 {
		f.ordinals = ordinals
	}
	return dropped, nil
}

// sectionOf returns the input ordinal of the section a symbol is defined
// in, or 0. Stabs record one too.
func (s machoSymbol) sectionOf() int {
	if s.typ&nType == nSect || s.stab() {
		return int(s.sect)
	}
	return 0
}

// sectionReference returns the input section ordinal that a non-extern
// relocation word names, or 0 for an absolute one or an ARM64 addend.
func (f *machoFile) sectionReference(word uint32) int {
	if word&relocExtern != 0 || f.cputype == cpuARM64 && word>>28 == arm64RelocAddend {
		return 0
	}
	return int(word & (relocSymbolMax - 1))
}

func (f *machoFile) removed(ordinal int) bool {
	return f.ordinals != nil && ordinal > 0 && ordinal < len(f.ordinals) && f.ordinals[ordinal] == 0
}

// editMachO applies the edits to an object, matching C names. It always
// rebuilds the symbol table in the order ld64 and LLVM write: locals in input
// order, then external definitions and undefined symbols, each sorted by name.
func editMachO(data []byte, e Edits) (objectResult, error) {
	f, err := parseMachO(data)
	if err != nil {
		return objectResult{}, err
	}
	if e.empty() {
		return objectResult{data: data}, nil
	}
	if f.symtab == 0 {
		if e.editsSections() {
			return objectResult{}, errors.New("section edits need a Mach-O symbol table")
		}
		return objectResult{data: data}, nil
	}
	droppedCount, err := f.sectionOrdinals(e)
	if err != nil {
		return objectResult{}, err
	}
	symbols := append([]machoSymbol{}, f.symbols...)
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
			if name := s.cname(); name != "" && !s.undefined() {
				definedAt[name] = i
			}
		}
	}
	renamed := 0
	// Targets are input indices; added symbols follow the input's.
	retarget := map[uint32]uint32{}
	retargetAll := map[uint32]bool{} // also in debug and unwind data
	removed := make([]bool, n)
	for i, s := range f.symbols {
		name := s.cname()
		if name == "" {
			continue
		}
		to := name
		switch real, isReal := strings.CutPrefix(name, "__real_"); {
		case s.external() && wrapped[name] && s.undefined() && !s.common():
			to = "__wrap_" + name
		case s.external() && wrapped[name] && !s.undefined():
			target, ok := existing["___wrap_"+name]
			if !ok {
				target = len(symbols)
				existing["___wrap_"+name] = target
				symbols = append(symbols, machoSymbol{name: "___wrap_" + name, typ: nExt})
			}
			retarget[uint32(i)] = uint32(target)
		case s.external() && isReal && wrapped[real] && s.undefined() && !s.common():
			// The real symbol is defined here: bind its references directly,
			// since an object should not both define and import one name.
			if def, ok := definedAt[real]; ok {
				retarget[uint32(i)], retargetAll[uint32(i)] = uint32(def), true
				removed[i] = true
				renamed++
				continue
			}
			to = real
		default:
			if r, ok := e.Rename[name]; ok {
				to = r
			}
		}
		if to != name {
			symbols[i].name = "_" + to
			renamed++
		}
	}
	out := bytes.Clone(data)
	retargeted := 0
	if len(retarget) > 0 {
		err := f.relocations(out, func(s machoSection, off int) error {
			word := le.Uint32(out[off:])
			target, ok := retarget[word&(relocSymbolMax-1)]
			if word&relocExtern == 0 || !ok {
				return nil
			}
			// Debug and unwind data describe the definition.
			if !retargetAll[word&(relocSymbolMax-1)] && (s.flags&sAttrDebug != 0 || s.segname == "__LD" || s.sectname == "__eh_frame") {
				return nil
			}
			le.PutUint32(out[off:], word&^(relocSymbolMax-1)|target)
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
	err = f.relocations(out, func(s machoSection, off int) error {
		word := le.Uint32(out[off:])
		if word&relocExtern != 0 {
			sym := word & (relocSymbolMax - 1)
			if int(sym) >= len(referenced) {
				return fmt.Errorf("Mach-O relocation names symbol %d of %d", sym, len(referenced))
			}
			referenced[sym] = true
		} else if k := f.sectionReference(word); f.removed(k) {
			return fmt.Errorf("cannot remove Mach-O section %s: a kept relocation in %s refers to it", f.sections[k-1].name(), s.name())
		}
		return nil
	})
	if err != nil {
		return objectResult{}, err
	}
	indirect := f.indirect(out)
	for i := 0; i+4 <= len(indirect); i += 4 {
		if sym := le.Uint32(indirect[i:]); sym&(indirectLocal|indirectAbs) == 0 {
			if int(sym) >= n {
				return objectResult{}, fmt.Errorf("Mach-O indirect symbol %d is out of range", sym)
			}
			referenced[sym] = true
		}
	}
	rebound, removedCount := 0, 0
	var hidden []string
	for i, s := range f.symbols {
		if removed[i] {
			continue
		}
		if symbols[i].typ&nType != s.typ&nType {
			continue // -add-symbol defined it
		}
		v := s.view()
		bind := e.binding(v)
		local := bind == elf.STB_LOCAL
		name := s.cname()
		// Removing such a symbol would let the linker dead strip its atom.
		kept := referenced[i] || !s.stab() && s.desc&(nNoDeadStrip|referencedDynamically) != 0
		switch {
		case f.removed(s.sectionOf()):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("cannot remove Mach-O section %s: a kept relocation or indirect symbol names %s, defined in it", f.sections[s.sect-1].name(), s.name)
			}
			removed[i] = true
		case name != "" && e.Strip.Match(name):
			if kept {
				return objectResult{}, fmt.Errorf("not stripping symbol %s because a relocation or indirect symbol names it, or it is marked no-dead-strip", name)
			}
			removed[i] = true
		case e.StripUnneeded && !kept && !s.stab() && !s.common() && (local || s.undefined()):
			removed[i] = true
		}
		if removed[i] {
			removedCount++
		} else if bind != elf.ST_BIND(v.info) {
			symbols[i].typ, symbols[i].desc = s.rebind(bind)
			rebound++
		}
		if name != "" && s.external() && (!s.undefined() || s.common()) && (removed[i] || local) {
			hidden = append(hidden, strings.TrimPrefix(symbols[i].name, "_"))
		}
	}
	edited := renamed + retargeted + rebound + removedCount + droppedCount + len(e.AddSymbols)
	if edited == 0 {
		return objectResult{data: data}, nil
	}
	if err := f.dropHints(&out); err != nil {
		return objectResult{}, err
	}
	if err := f.rewrite(&out, symbols, removed); err != nil {
		return objectResult{}, err
	}
	if f.ordinals != nil {
		f.compactSections(out)
	}
	return objectResult{data: out, edited: edited, hidden: hidden, added: added}, nil
}

// addSymbols applies -add-symbol. A value is an offset in its section, as
// in ELF relocatable objects. Hidden makes an external symbol a private
// extern; Mach-O has no protected visibility, and the symbol type has no
// equivalent. An undefined symbol of the name becomes the definition, so
// the object's references bind to it. It returns the names it defines
// externally.
func (f *machoFile) addSymbols(symbols *[]machoSymbol, adds []AddedSymbol) ([]string, error) {
	// Names are output names: those after renames and wraps.
	existing := map[string]int{}
	for i, s := range *symbols {
		if _, ok := existing[s.name]; !ok && s.external() {
			existing[s.name] = i
		}
	}
	var added []string
	for _, a := range adds {
		s := machoSymbol{name: "_" + a.Name, typ: nAbs, value: a.Value}
		if a.Section != "" {
			k := 0
			for j, sec := range f.sections {
				if sec.name() == a.Section {
					k = j + 1
					break
				}
			}
			if k == 0 || f.removed(k) {
				return nil, fmt.Errorf("cannot add symbol %s to missing Mach-O section %s; name it SEGMENT,SECTION", a.Name, a.Section)
			}
			s.typ, s.sect, s.value = nSect, byte(k), f.sections[k-1].addr+a.Value
		}
		switch a.Bind {
		case elf.STB_WEAK:
			s.typ |= nExt
			s.desc |= nWeakDef
		case elf.STB_GLOBAL:
			s.typ |= nExt
		}
		switch a.Visibility {
		case elf.STV_HIDDEN:
			if s.typ&nExt != 0 {
				s.typ |= nPext
			}
		case elf.STV_PROTECTED:
			return nil, fmt.Errorf("cannot add symbol %s: Mach-O has no protected visibility", a.Name)
		}
		if s.typ&nExt != 0 {
			added = append(added, a.Name)
		}
		if at, ok := existing[s.name]; ok {
			if old := (*symbols)[at]; !old.undefined() || old.common() {
				return nil, fmt.Errorf("cannot add symbol %s, which is already defined", a.Name)
			}
			(*symbols)[at] = s
			continue
		}
		if s.typ&nExt != 0 {
			existing[s.name] = len(*symbols)
		}
		*symbols = append(*symbols, s)
	}
	return added, nil
}

// dropHints removes the data-in-code entries and linker optimization hints
// that describe addresses in removed sections. Neither is needed for
// correctness, and a kept one would name an address no section holds.
func (f *machoFile) dropHints(out *[]byte) error {
	if f.ordinals == nil {
		return nil
	}
	gone := func(addr uint64) bool {
		for k, s := range f.sections {
			if f.ordinals[k+1] == 0 && addr >= s.addr && addr-s.addr < s.size {
				return true
			}
		}
		return false
	}
	place := func(cmd int, kept []byte) {
		for len(*out)%8 != 0 {
			*out = append(*out, 0)
		}
		le.PutUint32((*out)[cmd+8:], uint32(len(*out)))
		le.PutUint32((*out)[cmd+12:], uint32(len(kept)))
		*out = append(*out, kept...)
	}
	blob := func(cmd int) []byte {
		off, size := le.Uint32(f.data[cmd+8:]), le.Uint32(f.data[cmd+12:])
		return f.data[off : off+size]
	}
	if f.dataInCode != 0 {
		// Entries are an address, a length and a kind.
		old := blob(f.dataInCode)
		var kept []byte
		for i := 0; i+8 <= len(old); i += 8 {
			if !gone(uint64(le.Uint32(old[i:]))) {
				kept = append(kept, old[i:i+8]...)
			}
		}
		if len(kept) != len(old) {
			place(f.dataInCode, kept)
		}
	}
	if f.hints != 0 {
		// Each hint is a kind, an address count and the addresses, all
		// ULEB128; zeros pad the list.
		old := blob(f.hints)
		var kept []byte
		changed := false
		uleb := func(data []byte) (uint64, []byte, error) {
			v, k := binary.Uvarint(data)
			if k <= 0 {
				return 0, nil, errors.New("malformed Mach-O linker optimization hints")
			}
			return v, data[k:], nil
		}
		for data := old; len(data) > 0; {
			start := data
			kind, rest, err := uleb(data)
			if err != nil {
				return err
			}
			if kind == 0 {
				break
			}
			count, rest, err := uleb(rest)
			if err != nil {
				return err
			}
			drop := false
			for j := uint64(0); j < count; j++ {
				var addr uint64
				if addr, rest, err = uleb(rest); err != nil {
					return err
				}
				drop = drop || gone(addr)
			}
			if drop {
				changed = true
			} else {
				kept = append(kept, start[:len(start)-len(rest)]...)
			}
			data = rest
		}
		if changed {
			for len(kept)%8 != 0 {
				kept = append(kept, 0)
			}
			place(f.hints, kept)
		}
	}
	return nil
}

// compactSections rewrites the segment commands without the headers of
// removed sections. The segments keep their extents and the removed
// sections' bytes stay unreferenced, so no other offset moves; the load
// commands after a segment move up and the space they leave is zeroed.
func (f *machoFile) compactSections(out []byte) {
	ncmds, sizeofcmds := le.Uint32(out[16:]), int(le.Uint32(out[20:]))
	cmds := out[machoHeader64 : machoHeader64+sizeofcmds]
	packed := make([]byte, 0, len(cmds))
	ordinal := 0
	for i, off := uint32(0), 0; i < ncmds; i++ {
		c := cmds[off : off+int(le.Uint32(cmds[off+4:]))]
		off += len(c)
		if le.Uint32(c) != lcSegment64 {
			packed = append(packed, c...)
			continue
		}
		n := int(le.Uint32(c[64:]))
		seg := append([]byte{}, c[:72]...)
		kept := 0
		for j := 0; j < n; j++ {
			ordinal++
			if f.ordinals[ordinal] != 0 {
				seg = append(seg, c[72+80*j:72+80*(j+1)]...)
				kept++
			}
		}
		seg = append(seg, c[72+80*n:]...)
		le.PutUint32(seg[4:], uint32(len(seg)))
		le.PutUint32(seg[64:], uint32(kept))
		packed = append(packed, seg...)
	}
	copy(cmds, packed)
	clear(cmds[len(packed):])
	le.PutUint32(out[20:], uint32(len(packed)))
}

// rewrite places a new symbol and string table at the end of out, then
// renumbers extern relocations, indirect symbols and, when sections go,
// section ordinals. Entries of symbols past the input's are added ones.
func (f *machoFile) rewrite(out *[]byte, symbols []machoSymbol, removed []bool) error {
	n := len(f.symbols)
	var locals, defs, undefs []int
	for i, s := range symbols {
		switch {
		case i < n && removed[i]:
		case !s.external():
			locals = append(locals, i)
		case s.undefined():
			undefs = append(undefs, i)
		default:
			defs = append(defs, i)
		}
	}
	byName := func(group []int) {
		sort.SliceStable(group, func(a, b int) bool { return symbols[group[a]].name < symbols[group[b]].name })
	}
	byName(defs)
	byName(undefs)
	order := append(append(append([]int{}, locals...), defs...), undefs...)
	if len(order) >= relocSymbolMax {
		return errors.New("too many Mach-O symbols for relocations")
	}
	index := make([]uint32, len(symbols))
	for i := range index {
		index[i] = removedIndex
	}
	for j, i := range order {
		index[i] = uint32(j)
	}
	err := f.relocations(*out, func(_ machoSection, off int) error {
		word := le.Uint32((*out)[off:])
		if word&relocExtern == 0 {
			if k := f.sectionReference(word); k != 0 && f.ordinals != nil && k < len(f.ordinals) {
				le.PutUint32((*out)[off:], word&^(relocSymbolMax-1)|uint32(f.ordinals[k]))
			}
			return nil
		}
		sym := index[word&(relocSymbolMax-1)]
		if sym == removedIndex {
			return errors.New("Mach-O relocation names a removed symbol")
		}
		le.PutUint32((*out)[off:], word&^(relocSymbolMax-1)|sym)
		return nil
	})
	if err != nil {
		return err
	}
	indirect := f.indirect(*out)
	for i := 0; i+4 <= len(indirect); i += 4 {
		if sym := le.Uint32(indirect[i:]); sym&(indirectLocal|indirectAbs) == 0 {
			if index[sym] == removedIndex {
				return errors.New("Mach-O indirect symbol names a removed symbol")
			}
			le.PutUint32(indirect[i:], index[sym])
		}
	}
	// Keep the old strings, so unchanged names keep their offsets, and
	// append the new ones. The first string is the empty name at offset 0.
	oldOff, oldSize := le.Uint32((*out)[f.symtab+16:]), le.Uint32((*out)[f.symtab+20:])
	strtab := bytes.Clone((*out)[oldOff : oldOff+oldSize])
	offsets := map[string]uint32{}
	table := make([]byte, 0, len(order)*nlistSize)
	for _, i := range order {
		s := symbols[i]
		entry := make([]byte, nlistSize)
		if i < n {
			copy(entry, f.data[le.Uint32(f.data[f.symtab+8:])+uint32(i)*nlistSize:])
		}
		if i >= n || s.name != f.symbols[i].name {
			off, ok := offsets[s.name]
			if !ok {
				if uint64(len(strtab))+uint64(len(s.name)) >= 1<<32 {
					return errors.New("Mach-O string table is too large")
				}
				off = uint32(len(strtab))
				strtab = append(append(strtab, s.name...), 0)
				offsets[s.name] = off
			}
			le.PutUint32(entry, off)
		}
		entry[4], entry[5] = s.typ, s.sect
		if k := s.sectionOf(); f.ordinals != nil && k > 0 && k < len(f.ordinals) {
			entry[5] = byte(f.ordinals[k])
		}
		le.PutUint16(entry[6:], s.desc)
		le.PutUint64(entry[8:], s.value)
		table = append(table, entry...)
	}
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}
	for len(*out)%8 != 0 {
		*out = append(*out, 0)
	}
	if uint64(len(*out))+uint64(len(table))+uint64(len(strtab)) >= 1<<32 {
		return errors.New("Mach-O object is too large")
	}
	c := (*out)[f.symtab:]
	le.PutUint32(c[8:], uint32(len(*out)))
	le.PutUint32(c[12:], uint32(len(order)))
	le.PutUint32(c[16:], uint32(len(*out)+len(table)))
	le.PutUint32(c[20:], uint32(len(strtab)))
	if f.dysymtab != 0 {
		d := (*out)[f.dysymtab:]
		le.PutUint32(d[8:], 0)
		le.PutUint32(d[12:], uint32(len(locals)))
		le.PutUint32(d[16:], uint32(len(locals)))
		le.PutUint32(d[20:], uint32(len(defs)))
		le.PutUint32(d[24:], uint32(len(locals)+len(defs)))
		le.PutUint32(d[28:], uint32(len(undefs)))
	}
	*out = append(append(*out, table...), strtab...)
	return nil
}
