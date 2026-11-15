package symedit

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/moriyoshi/bao/ar"
)

func regularMembers(data []byte) ([]ar.Member, error) {
	members, err := ar.Parse(data)
	if err != nil {
		return nil, err
	}
	out := members[:0]
	for _, m := range members {
		if m.Kind == ar.Regular {
			out = append(out, m)
		}
	}
	return out, nil
}

// object is a parsed relocatable object of either format. Names are those
// that edits match: ELF symbol names and Mach-O C names.
type object interface {
	defined() []string
	undefined() []string
	// indexNames are the raw names an archive symbol index lists.
	indexNames() []string
}

func parseObject(data []byte) (object, error) {
	switch {
	case isMachO(data):
		return parseMachO(data)
	case isCOFF(data):
		return parseCOFF(data)
	}
	return parseELF(data)
}

func editObject(data []byte, e Edits) (objectResult, error) {
	switch {
	case isMachO(data):
		return editMachO(data, e)
	case isCOFF(data):
		return editCOFF(data, e)
	}
	return editELF(data, e)
}

// editArchive edits every member and writes an archive with a new symbol
// index, which a searched archive needs once its definitions are renamed:
// GNU format for ELF members and BSD format for Mach-O members, as their
// linkers expect.
func editArchive(data []byte, e Edits) ([]byte, int, error) {
	members, err := regularMembers(data)
	if err != nil {
		return nil, 0, err
	}
	total := 0
	hiddenBy := map[string]int{}
	for i, m := range members {
		r, err := editObject(m.Data, e)
		if err != nil {
			return nil, 0, fmt.Errorf("archive member %s: %w", m.Name, err)
		}
		members[i].Data = r.data
		total += r.edited
		for _, name := range r.hidden {
			hiddenBy[name] = i
		}
	}
	if total == 0 {
		return data, 0, nil
	}
	if len(hiddenBy) > 0 {
		if err := checkHidden(members, hiddenBy); err != nil {
			return nil, 0, err
		}
	}
	out, err := writeArchive(members)
	return out, total, err
}

// checkHidden rejects a member reference that bound to a definition another
// member no longer exports, unless some member still exports that name.
func checkHidden(members []ar.Member, hiddenBy map[string]int) error {
	files := make([]object, len(members))
	exported := map[string]bool{}
	for i, m := range members {
		f, err := parseObject(m.Data)
		if err != nil {
			return fmt.Errorf("archive member %s: %w", m.Name, err)
		}
		files[i] = f
		for _, name := range f.defined() {
			exported[name] = true
		}
	}
	for i, f := range files {
		for _, name := range f.undefined() {
			owner, ok := hiddenBy[name]
			if !ok || owner == i || exported[name] {
				continue
			}
			return fmt.Errorf("archive member %s refers to %s, which member %s no longer exports; partially link the archive into one object first, or use a prefix instead", members[i].Name, name, members[owner].Name)
		}
	}
	return nil
}

type indexed struct {
	member int
	name   string
}

func writeArchive(members []ar.Member) ([]byte, error) {
	var symbols []indexed
	names, machO, coff := 0, 0, 0
	for i, m := range members {
		f, err := parseObject(m.Data)
		if err != nil {
			return nil, fmt.Errorf("archive member %s: %w", m.Name, err)
		}
		if isMachO(m.Data) {
			machO++
		} else if isCOFF(m.Data) {
			coff++
		}
		for _, name := range f.indexNames() {
			symbols = append(symbols, indexed{i, name})
			names += len(name) + 1
		}
	}
	if machO > 0 && machO < len(members) || coff > 0 && coff < len(members) {
		return nil, fmt.Errorf("archive mixes object formats")
	}
	if machO > 0 {
		return writeBSDArchive(members, symbols)
	}
	if coff > 0 {
		return writeCOFFArchive(members, symbols)
	}
	// GNU ar stores names up to 15 bytes inline, terminated by /.
	var longNames []byte
	headerNames := make([]string, len(members))
	for i, m := range members {
		if len(m.Name) <= 15 && !strings.ContainsAny(m.Name, "/ ") {
			headerNames[i] = m.Name + "/"
			continue
		}
		headerNames[i] = fmt.Sprintf("/%d", len(longNames))
		longNames = append(append(longNames, m.Name...), "/\n"...)
	}
	padded := func(n int) int { return n + n%2 }
	// The index precedes the members, so its width decides their offsets.
	layout := func(word int) ([]int, int) {
		offset := 8 + 60 + padded(word+word*len(symbols)+names)
		if len(longNames) > 0 {
			offset += 60 + padded(len(longNames))
		}
		offsets := make([]int, len(members))
		for i, m := range members {
			offsets[i] = offset
			offset += 60 + padded(len(m.Data))
		}
		return offsets, offset
	}
	word, indexName := 4, "/"
	offsets, size := layout(word)
	if len(offsets) > 0 && uint64(offsets[len(offsets)-1]) > 0xffffffff {
		word, indexName = 8, "/SYM64/"
		offsets, size = layout(word)
	}
	out := make([]byte, 0, size)
	out = append(out, "!<arch>\n"...)
	member := func(name string, data []byte) {
		out = fmt.Appendf(out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "644", len(data))
		out = append(out, data...)
		if len(data)%2 != 0 {
			out = append(out, '\n')
		}
	}
	index := make([]byte, 0, word+word*len(symbols)+names)
	put := func(v int) {
		if word == 8 {
			index = binary.BigEndian.AppendUint64(index, uint64(v))
		} else {
			index = binary.BigEndian.AppendUint32(index, uint32(v))
		}
	}
	put(len(symbols))
	for _, s := range symbols {
		put(offsets[s.member])
	}
	for _, s := range symbols {
		index = append(append(index, s.name...), 0)
	}
	member(indexName, index)
	if len(longNames) > 0 {
		member("//", longNames)
	}
	for i, m := range members {
		member(headerNames[i], m.Data)
	}
	return out, nil
}

// writeBSDArchive writes the archive format of Apple's ar and ranlib: names in
// #1/N extended headers, padded so that each object starts 8-byte aligned,
// after a __.SYMDEF (or __.SYMDEF_64) index of member header offsets.
func writeBSDArchive(members []ar.Member, symbols []indexed) ([]byte, error) {
	var strtab []byte
	strx := make([]int, len(symbols))
	for i, s := range symbols {
		strx[i] = len(strtab)
		strtab = append(append(strtab, s.name...), 0)
	}
	for len(strtab)%8 != 0 {
		strtab = append(strtab, 0)
	}
	// Each name is padded so that the data after it is 8-byte aligned.
	entry := func(offset int, name string, size int) (int, int) {
		pad := len(name) + 1
		for (offset+60+pad)%8 != 0 {
			pad++
		}
		total := 60 + pad + size
		return pad, total + total%2
	}
	layout := func(word int) ([]int, int, string) {
		indexName := "__.SYMDEF"
		if word == 8 {
			indexName = "__.SYMDEF_64"
		}
		offset := 8
		_, n := entry(offset, indexName, 2*word+2*word*len(symbols)+len(strtab))
		offset += n
		offsets := make([]int, len(members))
		for i, m := range members {
			offsets[i] = offset
			_, n := entry(offset, m.Name, len(m.Data))
			offset += n
		}
		return offsets, offset, indexName
	}
	word := 4
	offsets, size, indexName := layout(word)
	if size > 0xffffffff {
		word = 8
		offsets, size, indexName = layout(word)
	}
	index := make([]byte, 0, 2*word+2*word*len(symbols)+len(strtab))
	put := func(v int) {
		if word == 8 {
			index = binary.LittleEndian.AppendUint64(index, uint64(v))
		} else {
			index = binary.LittleEndian.AppendUint32(index, uint32(v))
		}
	}
	put(2 * word * len(symbols))
	for i, s := range symbols {
		put(strx[i])
		put(offsets[s.member])
	}
	put(len(strtab))
	index = append(index, strtab...)
	out := make([]byte, 0, size)
	out = append(out, "!<arch>\n"...)
	member := func(name string, data []byte) {
		pad, _ := entry(len(out), name, len(data))
		out = fmt.Appendf(out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", fmt.Sprintf("#1/%d", pad), 0, 0, 0, "644", pad+len(data))
		out = append(out, name...)
		out = append(out, make([]byte, pad-len(name))...)
		out = append(out, data...)
		if (pad+len(data))%2 != 0 {
			out = append(out, '\n')
		}
	}
	member(indexName, index)
	for _, m := range members {
		member(m.Name, m.Data)
	}
	return out, nil
}

// writeCOFFArchive writes the Microsoft library format that link.exe,
// lld-link and MinGW ld read: a first linker member as in GNU ar, a second
// one with little-endian member offsets and name-sorted symbols, and
// NUL-terminated long names.
func writeCOFFArchive(members []ar.Member, symbols []indexed) ([]byte, error) {
	var strs []byte
	for _, s := range symbols {
		strs = append(append(strs, s.name...), 0)
	}
	sorted := append([]indexed{}, symbols...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].name < sorted[b].name })
	var longNames []byte
	headerNames := make([]string, len(members))
	for i, m := range members {
		if len(m.Name) <= 15 && !strings.ContainsAny(m.Name, "/ ") {
			headerNames[i] = m.Name + "/"
			continue
		}
		headerNames[i] = fmt.Sprintf("/%d", len(longNames))
		longNames = append(append(longNames, m.Name...), 0)
	}
	padded := func(n int) int { return n + n%2 }
	first := 4 + 4*len(symbols) + len(strs)
	second := 4 + 4*len(members) + 4 + 2*len(symbols) + len(strs)
	offset := 8 + 60 + padded(first) + 60 + padded(second)
	if len(longNames) > 0 {
		offset += 60 + padded(len(longNames))
	}
	offsets := make([]int, len(members))
	for i, m := range members {
		offsets[i] = offset
		offset += 60 + padded(len(m.Data))
	}
	if offset > 0xffffffff || len(members) > 0xffff {
		return nil, fmt.Errorf("COFF archive is too large for its symbol index")
	}
	out := make([]byte, 0, offset)
	out = append(out, "!<arch>\n"...)
	member := func(name string, data []byte) {
		out = fmt.Appendf(out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "644", len(data))
		out = append(out, data...)
		if len(data)%2 != 0 {
			out = append(out, '\n')
		}
	}
	index := binary.BigEndian.AppendUint32(nil, uint32(len(symbols)))
	for _, s := range symbols {
		index = binary.BigEndian.AppendUint32(index, uint32(offsets[s.member]))
	}
	member("/", append(index, strs...))
	index = binary.LittleEndian.AppendUint32(nil, uint32(len(members)))
	for _, off := range offsets {
		index = binary.LittleEndian.AppendUint32(index, uint32(off))
	}
	index = binary.LittleEndian.AppendUint32(index, uint32(len(sorted)))
	for _, s := range sorted {
		index = binary.LittleEndian.AppendUint16(index, uint16(s.member+1))
	}
	for _, s := range sorted {
		index = append(append(index, s.name...), 0)
	}
	member("/", index)
	if len(longNames) > 0 {
		member("//", longNames)
	}
	for i, m := range members {
		member(headerNames[i], m.Data)
	}
	return out, nil
}
