package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// objectResult is one edited object.
type objectResult struct {
	data   []byte
	edited int
	// hidden lists the global definitions, by output name, that the edit made
	// local or removed. Other objects can no longer bind to them.
	hidden []string
}

const removedIndex = ^uint32(0)

func editELF(data []byte, e Edits) (objectResult, error) {
	f, err := parseELF(data)
	if err != nil {
		return objectResult{}, err
	}
	if e.empty() || f.symtab == 0 {
		return objectResult{data: data}, nil
	}
	n := len(f.symbols)
	wrapped := map[string]bool{}
	for _, name := range e.Wrap {
		wrapped[name] = true
	}
	// Indices below are input indices, followed by those of added symbols.
	// A rebuilt table maps both to output order at the end.
	names := make([]string, n)
	infos := make([]byte, n)
	existing := map[string]uint32{}
	for i, s := range f.symbols {
		names[i], infos[i] = s.name, s.info
		if s.global() && s.named() {
			if _, ok := existing[s.name]; !ok {
				existing[s.name] = uint32(i)
			}
		}
	}
	renamed := 0
	// A defined wrapped symbol keeps its definition. References to it move to
	// a __wrap_ symbol, which is reused when the object already has one.
	retarget := map[uint32]uint32{}
	var added []elfSymbol
	for i, s := range f.symbols {
		if i == 0 || !s.named() {
			continue
		}
		to := s.name
		switch real, isReal := strings.CutPrefix(s.name, "__real_"); {
		case s.global() && wrapped[s.name] && !s.defined():
			to = "__wrap_" + s.name
		case s.global() && wrapped[s.name]:
			target, ok := existing["__wrap_"+s.name]
			if !ok {
				target = uint32(n + len(added))
				existing["__wrap_"+s.name] = target
				// Keep the symbol type so a wrapped function stays a function.
				added = append(added, elfSymbol{name: "__wrap_" + s.name, info: elf.ST_INFO(elf.STB_GLOBAL, elf.ST_TYPE(s.info))})
			}
			retarget[uint32(i)] = target
		case s.global() && isReal && wrapped[real] && !s.defined():
			// An undefined NAME beside a defined NAME binds to it when linked.
			to = real
		default:
			if r, ok := e.Rename[s.name]; ok {
				to = r
			}
		}
		if to != s.name {
			names[i] = to
			renamed++
		}
		infos[i] = elf.ST_INFO(e.binding(s), elf.ST_TYPE(s.info))
	}
	var crel bool
	for _, s := range f.sections {
		crel = crel || s.typ == shtCREL && int(s.link) == f.symtab
	}
	if crel && (len(retarget) > 0 || !e.Visibility.empty()) {
		return objectResult{}, errors.New("CREL relocations are unsupported when redirecting references or changing symbol bindings; build without -Wa,--crel")
	}
	out := bytes.Clone(data)
	relocs := func(fn func(s elfSection, entry []byte) error) error {
		for i, s := range f.sections {
			if s.typ != elf.SHT_RELA && s.typ != elf.SHT_REL || int(s.link) != f.symtab {
				continue
			}
			size := uint64(16)
			if s.typ == elf.SHT_RELA {
				size = 24
			}
			if s.size%size != 0 {
				return fmt.Errorf("malformed ELF relocation section %d", i)
			}
			for off := s.offset; off < s.offset+s.size; off += size {
				if err := fn(s, out[off:off+size]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	retargeted := 0
	if len(retarget) > 0 {
		err := relocs(func(s elfSection, entry []byte) error {
			// Debug data describes the definition; only runtime references move.
			if int(s.info) >= len(f.sections) || f.sections[s.info].flags&elf.SHF_ALLOC == 0 {
				return nil
			}
			info := le.Uint64(entry[8:])
			if target, ok := retarget[uint32(info>>32)]; ok {
				le.PutUint64(entry[8:], uint64(target)<<32|info&0xffffffff)
				retargeted++
			}
			return nil
		})
		if err != nil {
			return objectResult{}, err
		}
	}
	if retargeted == 0 {
		added = nil
	}
	// Relocations and group signatures need their symbols.
	referenced := make([]bool, n+len(added))
	err = relocs(func(_ elfSection, entry []byte) error {
		sym := le.Uint64(entry[8:]) >> 32
		if sym >= uint64(len(referenced)) {
			return fmt.Errorf("ELF relocation names symbol %d of %d", sym, len(referenced))
		}
		referenced[sym] = true
		return nil
	})
	if err != nil {
		return objectResult{}, err
	}
	for _, s := range f.sections {
		if s.typ == elf.SHT_GROUP && int(s.link) == f.symtab && int(s.info) < n {
			referenced[s.info] = true
		}
	}
	removed := make([]bool, n)
	removedCount, rebound, reorder := 0, 0, false
	var hidden []string
	for i, s := range f.symbols {
		if i == 0 {
			continue
		}
		local := elf.ST_BIND(infos[i]) == elf.STB_LOCAL
		switch {
		case s.named() && e.Strip.Match(s.name):
			if referenced[i] {
				return objectResult{}, fmt.Errorf("not stripping symbol %s because a relocation or section group names it", s.name)
			}
			removed[i] = true
		case e.StripUnneeded && !referenced[i] && elf.ST_TYPE(s.info) != elf.STT_SECTION && !s.mapping() && (local || !s.defined()):
			removed[i] = true
		}
		if removed[i] {
			removedCount++
		} else if infos[i] != s.info {
			rebound++
		}
		reorder = reorder || removed[i] || local != (elf.ST_BIND(s.info) == elf.STB_LOCAL)
		if s.global() && s.defined() && s.named() && (removed[i] || local) {
			hidden = append(hidden, names[i])
		}
	}
	edited := renamed + retargeted + rebound + removedCount
	if edited == 0 {
		return objectResult{data: data}, nil
	}
	// Append new names to a copy of the string table so that existing offsets,
	// including shared suffixes and section names, keep their meaning.
	symtab := f.sections[f.symtab]
	strtab := bytes.Clone(f.section(int(symtab.link)))
	offsets := map[string]uint32{}
	intern := func(name string) (uint32, error) {
		if off, ok := offsets[name]; ok {
			return off, nil
		}
		if uint64(len(strtab))+uint64(len(name)) >= 1<<32 {
			return 0, errors.New("ELF string table is too large")
		}
		off := uint32(len(strtab))
		strtab = append(append(strtab, name...), 0)
		offsets[name] = off
		return off, nil
	}
	entries := make([][]byte, n+len(added))
	for i := range entries {
		entry := make([]byte, symbolSize)
		if i < n {
			copy(entry, f.data[symtab.offset+uint64(i)*symbolSize:])
			entry[4] = infos[i]
			if names[i] != f.symbols[i].name {
				off, err := intern(names[i])
				if err != nil {
					return objectResult{}, err
				}
				le.PutUint32(entry, off)
			}
		} else {
			off, err := intern(added[i-n].name)
			if err != nil {
				return objectResult{}, err
			}
			le.PutUint32(entry, off)
			entry[4] = added[i-n].info
		}
		entries[i] = entry
	}
	header := func(i int) []byte { return out[f.shoff+uint64(i)*sectionHeaderSize:] }
	place := func(i int, content []byte, align int) {
		for len(out)%align != 0 {
			out = append(out, 0)
		}
		le.PutUint64(header(i)[24:], uint64(len(out)))
		le.PutUint64(header(i)[32:], uint64(len(content)))
		out = append(out, content...)
	}
	if !reorder {
		symbols := bytes.Join(entries, nil)
		if len(added) == 0 {
			copy(out[symtab.offset:], symbols)
		} else {
			place(f.symtab, symbols, 8)
			for i, s := range f.sections {
				if s.typ == elf.SHT_SYMTAB_SHNDX && int(s.link) == f.symtab {
					// New symbols are undefined, so their extended index is zero.
					place(i, append(bytes.Clone(f.section(i)), make([]byte, 4*len(added))...), 4)
				}
			}
		}
	} else if err := f.reorder(&out, entries, infos, removed, place, header); err != nil {
		return objectResult{}, err
	}
	if len(offsets) > 0 {
		place(int(symtab.link), strtab, 1)
	}
	return objectResult{data: out, edited: edited, hidden: hidden}, nil
}

// reorder writes a symbol table whose local symbols precede the others, as
// ELF requires, without the removed ones, and renumbers every reference to a
// symbol index. entries beyond the input's symbols are added globals.
func (f *elfFile) reorder(out *[]byte, entries [][]byte, infos []byte, removed []bool, place func(int, []byte, int), header func(int) []byte) error {
	n := len(f.symbols)
	order := []int{0}
	for pass := 0; pass < 2; pass++ {
		for i := 1; i < len(entries); i++ {
			if i < n && removed[i] {
				continue
			}
			local := i < n && elf.ST_BIND(infos[i]) == elf.STB_LOCAL
			if local == (pass == 0) {
				order = append(order, i)
			}
		}
		if pass == 0 {
			binary.LittleEndian.PutUint32(header(f.symtab)[44:], uint32(len(order)))
		}
	}
	index := make([]uint32, len(entries))
	for i := range index {
		index[i] = removedIndex
	}
	for j, i := range order {
		index[i] = uint32(j)
	}
	renumber := func(old uint64) (uint32, error) {
		if old >= uint64(len(index)) || index[old] == removedIndex {
			return 0, fmt.Errorf("ELF reference to removed symbol %d", old)
		}
		return index[old], nil
	}
	for i, s := range f.sections {
		if i == 0 || int(s.link) != f.symtab {
			continue
		}
		switch s.typ {
		case elf.SHT_REL, elf.SHT_RELA:
			size := uint64(16)
			if s.typ == elf.SHT_RELA {
				size = 24
			}
			for off := s.offset; off < s.offset+s.size; off += size {
				info := le.Uint64((*out)[off+8:])
				if info>>32 == 0 {
					continue
				}
				sym, err := renumber(info >> 32)
				if err != nil {
					return err
				}
				le.PutUint64((*out)[off+8:], uint64(sym)<<32|info&0xffffffff)
			}
		case elf.SHT_GROUP:
			sym, err := renumber(uint64(s.info))
			if err != nil {
				return err
			}
			le.PutUint32(header(i)[44:], sym)
		case elf.SHT_SYMTAB_SHNDX:
			old := f.section(i)
			if len(old) != 4*n {
				return fmt.Errorf("ELF extended section index table %d does not match its symbol table", i)
			}
			table := make([]byte, 4*len(order))
			for j, k := range order {
				if k < n {
					copy(table[4*j:], old[4*k:4*k+4])
				}
			}
			place(i, table, 4)
		case shtLLVMAddrsig:
			table, err := renumberAddrsig(f.section(i), renumber, removed)
			if err != nil {
				return err
			}
			place(i, table, 1)
		case shtLLVMCGProf:
			// Since LLVM 13 its symbols are in a relocation section; older
			// entries embed two symbol indices each.
			if s.entsize != 8 {
				return fmt.Errorf("ELF call graph profile section %d stores symbol indices", i)
			}
		default:
			return fmt.Errorf("ELF section %d of type %#x refers to symbol indices that cannot be renumbered", i, uint32(s.typ))
		}
	}
	symbols := make([]byte, 0, len(order)*symbolSize)
	for _, i := range order {
		symbols = append(symbols, entries[i]...)
	}
	place(f.symtab, symbols, 8)
	return nil
}

// renumberAddrsig rewrites LLVM's address-significance table, a ULEB128 list
// of symbol indices. A removed symbol needs no entry.
func renumberAddrsig(data []byte, renumber func(uint64) (uint32, error), removed []bool) ([]byte, error) {
	var out []byte
	for len(data) > 0 {
		v, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, errors.New("malformed LLVM address-significance table")
		}
		data = data[n:]
		if v < uint64(len(removed)) && removed[v] {
			continue
		}
		sym, err := renumber(v)
		if err != nil {
			return nil, err
		}
		out = binary.AppendUvarint(out, uint64(sym))
	}
	return out, nil
}

// binding applies llvm-objcopy's order: localize, keep-global, globalize,
// then weaken. Undefined and common symbols are never made local. A wrap
// applies to every input of the link, so -keep-global-symbol and
// -localize-hidden leave a wrapped symbol's definition and its __wrap_
// wrapper global; only naming one with -localize-symbol hides it.
func (e Edits) binding(s elfSymbol) elf.SymBind {
	v := e.Visibility
	b := elf.ST_BIND(s.info)
	if !s.named() {
		return b
	}
	if s.defined() && !s.common() {
		linked := e.wrapLinked(s.name)
		vis := elf.SymVis(s.other & 3)
		if v.LocalizeHidden && !linked && (vis == elf.STV_HIDDEN || vis == elf.STV_INTERNAL) || v.Localize.Match(s.name) {
			b = elf.STB_LOCAL
		}
		if !v.KeepGlobal.empty() && !linked && !v.KeepGlobal.Match(s.name) {
			b = elf.STB_LOCAL
		}
	}
	if s.defined() && v.Globalize.Match(s.name) {
		b = elf.STB_GLOBAL
	}
	if b != elf.STB_LOCAL && v.Weaken.Match(s.name) {
		b = elf.STB_WEAK
	}
	return b
}

// wrapLinked reports a wrapped symbol or its wrapper.
func (e Edits) wrapLinked(name string) bool {
	for _, w := range e.Wrap {
		if name == w || name == "__wrap_"+w {
			return true
		}
	}
	return false
}
