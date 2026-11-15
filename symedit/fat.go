package symedit

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Universal (fat) Mach-O files hold one object or archive per architecture,
// behind a big-endian header: FAT_MAGIC with 20-byte fat_arch entries or
// FAT_MAGIC_64 with 32-byte fat_arch_64 entries.
const (
	fatMagic   = 0xcafebabe
	fatMagic64 = 0xcafebabf
)

var be = binary.BigEndian

type fatSlice struct {
	cputype, subtype uint32
	offset, size     uint64
	align            uint32
	reserved         uint32
}

// isFat reports a universal file. Java class files share FAT_MAGIC, but their
// version would make an implausible architecture count.
func isFat(data []byte) bool {
	if len(data) < 8 || be.Uint32(data) != fatMagic && be.Uint32(data) != fatMagic64 {
		return false
	}
	n := be.Uint32(data[4:])
	return n > 0 && n < 32
}

func parseFat(data []byte) ([]fatSlice, bool, error) {
	wide := be.Uint32(data) == fatMagic64
	n := int(be.Uint32(data[4:]))
	entry := 20
	if wide {
		entry = 32
	}
	if 8+n*entry > len(data) {
		return nil, false, errors.New("universal Mach-O architecture table is out of range")
	}
	slices := make([]fatSlice, n)
	for i := range slices {
		e := data[8+i*entry:]
		s := fatSlice{cputype: be.Uint32(e), subtype: be.Uint32(e[4:])}
		if wide {
			s.offset, s.size, s.align, s.reserved = be.Uint64(e[8:]), be.Uint64(e[16:]), be.Uint32(e[24:]), be.Uint32(e[28:])
		} else {
			s.offset, s.size, s.align = uint64(be.Uint32(e[8:])), uint64(be.Uint32(e[12:])), be.Uint32(e[16:])
		}
		if s.offset > uint64(len(data)) || s.size > uint64(len(data))-s.offset || s.align > 15 {
			return nil, false, fmt.Errorf("universal Mach-O slice %s is out of range", s.arch())
		}
		slices[i] = s
	}
	return slices, wide, nil
}

func (s fatSlice) arch() string {
	switch s.cputype {
	case 0x01000007:
		return "x86_64"
	case 0x0100000c:
		if s.subtype&0xff == 2 {
			return "arm64e"
		}
		return "arm64"
	case 7:
		return "i386"
	case 12:
		return "arm"
	case 0x0200000c:
		return "arm64_32"
	}
	return fmt.Sprintf("cputype %#x", s.cputype)
}

// fatSlices returns each slice's bytes.
func fatSlices(data []byte) ([][]byte, []fatSlice, bool, error) {
	slices, wide, err := parseFat(data)
	if err != nil {
		return nil, nil, false, err
	}
	out := make([][]byte, len(slices))
	for i, s := range slices {
		out[i] = data[s.offset : s.offset+s.size]
		if isFat(out[i]) {
			return nil, nil, false, errors.New("nested universal Mach-O files are unsupported")
		}
	}
	return out, slices, wide, nil
}

// editFat edits every slice, an object or an archive, and writes a universal
// file with the same architectures, order and alignments.
func editFat(data []byte, e Edits) ([]byte, int, error) {
	parts, slices, wide, err := fatSlices(data)
	if err != nil {
		return nil, 0, err
	}
	total := 0
	for i, part := range parts {
		var n int
		if isArchive(part) {
			parts[i], n, err = editArchive(part, e)
		} else {
			var r objectResult
			r, err = editObject(part, e)
			parts[i], n = r.data, r.edited
		}
		if err != nil {
			return nil, 0, fmt.Errorf("universal Mach-O slice %s: %w", slices[i].arch(), err)
		}
		total += n
	}
	if total == 0 {
		return data, 0, nil
	}
	entry := 20
	if wide {
		entry = 32
	}
	out := make([]byte, 8+len(slices)*entry)
	copy(out, data[:8])
	for i, s := range slices {
		for len(out)%(1<<s.align) != 0 {
			out = append(out, 0)
		}
		s.offset, s.size = uint64(len(out)), uint64(len(parts[i]))
		if !wide && (s.offset+s.size) >= 1<<32 {
			return nil, 0, errors.New("universal Mach-O file is too large for 32-bit offsets")
		}
		h := out[8+i*entry:]
		be.PutUint32(h, s.cputype)
		be.PutUint32(h[4:], s.subtype)
		if wide {
			be.PutUint64(h[8:], s.offset)
			be.PutUint64(h[16:], s.size)
			be.PutUint32(h[24:], s.align)
			be.PutUint32(h[28:], s.reserved)
		} else {
			be.PutUint32(h[8:], uint32(s.offset))
			be.PutUint32(h[12:], uint32(s.size))
			be.PutUint32(h[16:], s.align)
		}
		out = append(out, parts[i]...)
	}
	return out, total, nil
}
