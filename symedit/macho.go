package symedit

import (
	"bytes"
	"debug/elf"
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
	nlistSize     = 16

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
)

type machoSection struct {
	segname, sectname string
	flags             uint32
	reloff, nreloc    uint32
}

type machoSymbol struct {
	name  string
	typ   byte
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
	sections []machoSection
	// Load command offsets; dysymtab is 0 when the object has none.
	symtab, dysymtab int
	symbols          []machoSymbol
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
	f := &machoFile{data: data}
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
					reloff: le.Uint32(h[56:]), nreloc: le.Uint32(h[60:]), flags: le.Uint32(h[64:]),
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
		f.symbols[i] = machoSymbol{name: name, typ: e[4], desc: le.Uint16(e[6:]), value: le.Uint64(e[8:])}
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

// relocations calls fn with each relocation's second word, by file offset.
func (f *machoFile) relocations(out []byte, fn func(s machoSection, off int) error) error {
	for _, s := range f.sections {
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

// editMachO applies the edits to an object, matching C names. It always
// rebuilds the symbol table in the order ld64 and LLVM write: locals in input
// order, then external definitions and undefined symbols, each sorted by name.
func editMachO(data []byte, e Edits) (objectResult, error) {
	f, err := parseMachO(data)
	if err != nil {
		return objectResult{}, err
	}
	if e.editsSections() {
		return objectResult{}, errors.New("section edits and added symbols are supported only for ELF, not Mach-O")
	}
	if e.empty() || f.symtab == 0 {
		return objectResult{data: data}, nil
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
	referenced := make([]bool, len(symbols))
	err = f.relocations(out, func(_ machoSection, off int) error {
		word := le.Uint32(out[off:])
		if word&relocExtern != 0 {
			sym := word & (relocSymbolMax - 1)
			if int(sym) >= len(referenced) {
				return fmt.Errorf("Mach-O relocation names symbol %d of %d", sym, len(referenced))
			}
			referenced[sym] = true
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
	for i, s := range f.symbols {
		// Removing such a symbol would let the linker dead strip its atom.
		if !s.stab() && s.desc&(nNoDeadStrip|referencedDynamically) != 0 {
			referenced[i] = true
		}
	}
	rebound, removedCount := 0, 0
	var hidden []string
	for i, s := range f.symbols {
		if removed[i] {
			continue
		}
		v := s.view()
		bind := e.binding(v)
		local := bind == elf.STB_LOCAL
		name := s.cname()
		switch {
		case name != "" && e.Strip.Match(name):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("not stripping symbol %s because a relocation or indirect symbol names it, or it is marked no-dead-strip", name)
			}
			removed[i] = true
		case e.StripUnneeded && !referenced[i] && !s.stab() && !s.common() && (local || s.undefined()):
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
	edited := renamed + retargeted + rebound + removedCount
	if edited == 0 {
		return objectResult{data: data}, nil
	}
	if err := f.rewrite(&out, symbols, removed); err != nil {
		return objectResult{}, err
	}
	return objectResult{data: out, edited: edited, hidden: hidden}, nil
}

// rewrite places a new symbol and string table at the end of out, then
// renumbers extern relocations and indirect symbols. Entries of symbols past
// the input's are added undefined symbols.
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
		entry[4] = s.typ
		le.PutUint16(entry[6:], s.desc)
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
