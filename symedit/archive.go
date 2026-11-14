package symedit

import (
	"encoding/binary"
	"fmt"
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

// editArchive edits every member and writes a GNU archive with a new symbol
// index, which a searched archive needs once its definitions are renamed.
func editArchive(data []byte, e Edits) ([]byte, int, error) {
	members, err := regularMembers(data)
	if err != nil {
		return nil, 0, err
	}
	total := 0
	for i, m := range members {
		edited, n, err := editELF(m.Data, e)
		if err != nil {
			return nil, 0, fmt.Errorf("archive member %s: %w", m.Name, err)
		}
		members[i].Data = edited
		total += n
	}
	if total == 0 {
		return data, 0, nil
	}
	out, err := writeArchive(members)
	return out, total, err
}

func writeArchive(members []ar.Member) ([]byte, error) {
	type indexed struct {
		member int
		name   string
	}
	var symbols []indexed
	names := 0
	for i, m := range members {
		f, err := parseELF(m.Data)
		if err != nil {
			return nil, fmt.Errorf("archive member %s: %w", m.Name, err)
		}
		for _, name := range f.defined() {
			symbols = append(symbols, indexed{i, name})
			names += len(name) + 1
		}
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
