package symedit

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// CREL is LLVM's compact relocation format (SHT_CREL, clang -Wa,--crel). A
// ULEB128 header holds count*8, 4 when addends are present, and an offset
// shift; each entry has a flags byte carrying the low bits of the offset
// delta, then SLEB128 deltas of the symbol index, type and addend that the
// flags select. See llvm/include/llvm/MC/MCELFExtras.h.

const crelHasAddend = 4

// decodeCREL returns the relocations as RELA entries, and whether the
// section stores addends.
func decodeCREL(data []byte) ([]byte, bool, error) {
	malformed := errors.New("malformed ELF CREL relocation section")
	hdr, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, false, malformed
	}
	data = data[n:]
	count, addend, shift := hdr/8, hdr&crelHasAddend != 0, hdr%crelHasAddend
	flagBits := uint(2)
	if addend {
		flagBits = 3
	}
	if count > uint64(len(data)) {
		return nil, false, malformed
	}
	out := make([]byte, 0, 24*count)
	var offset, add uint64
	var sym, typ uint32
	for ; count > 0; count-- {
		if len(data) == 0 {
			return nil, false, malformed
		}
		b := data[0]
		data = data[1:]
		offset += uint64(b) >> flagBits
		if b >= 0x80 {
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, false, malformed
			}
			data = data[n:]
			offset += v<<(7-flagBits) - 0x80>>flagBits
		}
		for _, field := range []struct {
			bit  byte
			into func(int64)
		}{{1, func(d int64) { sym += uint32(d) }}, {2, func(d int64) { typ += uint32(d) }}, {4, func(d int64) { add += uint64(d) }}} {
			if b&field.bit == 0 || field.bit == 4 && !addend {
				continue
			}
			d, n := readSLEB(data)
			if n <= 0 {
				return nil, false, malformed
			}
			data = data[n:]
			field.into(d)
		}
		out = le.AppendUint64(out, offset<<shift)
		out = le.AppendUint64(out, uint64(sym)<<32|uint64(typ))
		out = le.AppendUint64(out, add)
	}
	return out, addend, nil
}

// encodeCREL writes RELA entries as LLVM's encoder does, so an unchanged
// section encodes to the same bytes.
func encodeCREL(entries []byte, addend bool) []byte {
	count := uint64(len(entries) / 24)
	mask := uint64(8)
	for i := 0; i < len(entries); i += 24 {
		mask |= le.Uint64(entries[i:])
	}
	shift := uint(bits.TrailingZeros64(mask))
	hdr := count*8 + uint64(shift)
	flagBits := uint(2)
	if addend {
		hdr |= crelHasAddend
		flagBits = 3
	}
	out := binary.AppendUvarint(nil, hdr)
	var offset, add uint64
	var sym, typ uint32
	for i := 0; i < len(entries); i += 24 {
		off, info, a := le.Uint64(entries[i:]), le.Uint64(entries[i+8:]), le.Uint64(entries[i+16:])
		s, t := uint32(info>>32), uint32(info)
		delta := (off - offset) >> shift
		offset = off
		var flags uint64
		if s != sym {
			flags |= 1
		}
		if t != typ {
			flags |= 2
		}
		if addend && a != add {
			flags |= 4
		}
		b := delta<<flagBits | flags
		if delta < 0x80>>flagBits {
			out = append(out, byte(b))
		} else {
			out = append(out, byte(b)&0x7f|0x80)
			out = binary.AppendUvarint(out, delta>>(7-flagBits))
		}
		// Without addends, bit 2 of the first byte belongs to the offset.
		if flags&1 != 0 {
			out = appendSLEB(out, int64(int32(s-sym)))
			sym = s
		}
		if flags&2 != 0 {
			out = appendSLEB(out, int64(int32(t-typ)))
			typ = t
		}
		if flags&4 != 0 {
			out = appendSLEB(out, int64(a-add))
			add = a
		}
	}
	return out
}

func appendSLEB(out []byte, v int64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 && c&0x40 == 0 || v == -1 && c&0x40 != 0 {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

func readSLEB(data []byte) (int64, int) {
	var v int64
	var shift uint
	for i, c := range data {
		if shift >= 64 {
			return 0, -1
		}
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, i + 1
		}
	}
	return 0, 0
}
