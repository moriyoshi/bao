package translate

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
)

// libunwind looks up compact unwind information only for images dyld knows.
// A dylib loaded into private memory needs DWARF FDEs registered with
// __register_frame instead: DWARF-mode entries already point at the dylib's
// __eh_frame records, and the compact encodings are converted here. Encoding
// and layout facts come from the SDK's public compact_unwind_encoding.h.

// DylibUnwind holds synthesized DWARF CFI. It is appended to the loaded image
// at Offset; absolute pointers in it are image rebases.
type DylibUnwind struct {
	Offset uint64
	// FDEs lists every FDE to register: synthesized ones and the dylib's own.
	FDEs []uint64
}

type compactEntry struct {
	function, length uint64
	encoding         uint32
	lsda             uint64
}

// compactEntries decodes the two-level __unwind_info table.
func (d *DylibImage) compactEntries() ([]compactEntry, []uint32, error) {
	r := d.CompactUnwind
	b := d.Image[r.Start:r.End]
	le := binary.LittleEndian
	if len(b) < 28 || le.Uint32(b) != 1 {
		return nil, nil, fmt.Errorf("unsupported __unwind_info version")
	}
	field := func(at, n uint32) ([]byte, error) {
		if uint64(at)+uint64(n) > uint64(len(b)) {
			return nil, fmt.Errorf("__unwind_info table outside the section")
		}
		return b[at : at+n], nil
	}
	common, err := field(le.Uint32(b[4:]), 4*le.Uint32(b[8:]))
	if err != nil {
		return nil, nil, err
	}
	personalityTable, err := field(le.Uint32(b[12:]), 4*le.Uint32(b[16:]))
	if err != nil {
		return nil, nil, err
	}
	var personalities []uint32
	for p := 0; p < len(personalityTable); p += 4 {
		personalities = append(personalities, le.Uint32(personalityTable[p:]))
	}
	index, err := field(le.Uint32(b[20:]), 12*le.Uint32(b[24:]))
	if err != nil {
		return nil, nil, err
	}
	var entries []compactEntry
	lsdas := map[uint64]uint64{}
	for i := 0; i+12 <= len(index); i += 12 {
		first, page, lsda := le.Uint32(index[i:]), le.Uint32(index[i+4:]), le.Uint32(index[i+8:])
		if i+24 <= len(index) {
			next := le.Uint32(index[i+20:])
			if next > lsda {
				table, err := field(lsda, next-lsda)
				if err != nil {
					return nil, nil, err
				}
				for p := 0; p+8 <= len(table); p += 8 {
					lsdas[uint64(le.Uint32(table[p:]))] = uint64(le.Uint32(table[p+4:]))
				}
			}
		}
		if page == 0 {
			continue // the sentinel entry
		}
		head, err := field(page, 8)
		if err != nil {
			return nil, nil, err
		}
		kind, at, count := le.Uint32(head), le.Uint16(head[4:]), le.Uint16(head[6:])
		switch kind {
		case 2: // UNWIND_SECOND_LEVEL_REGULAR
			table, err := field(page+uint32(at), 8*uint32(count))
			if err != nil {
				return nil, nil, err
			}
			for p := 0; p < len(table); p += 8 {
				entries = append(entries, compactEntry{function: uint64(le.Uint32(table[p:])), encoding: le.Uint32(table[p+4:])})
			}
		case 3: // UNWIND_SECOND_LEVEL_COMPRESSED
			head, err := field(page, 12)
			if err != nil {
				return nil, nil, err
			}
			local, err := field(page+uint32(le.Uint16(head[8:])), 4*uint32(le.Uint16(head[10:])))
			if err != nil {
				return nil, nil, err
			}
			table, err := field(page+uint32(at), 4*uint32(count))
			if err != nil {
				return nil, nil, err
			}
			for p := 0; p < len(table); p += 4 {
				v := le.Uint32(table[p:])
				e, which := v>>24, compactEntry{function: uint64(first) + uint64(v&0xffffff)}
				switch {
				case int(e) < len(common)/4:
					e, which.encoding = 0, le.Uint32(common[4*e:])
				case int(e)-len(common)/4 < len(local)/4:
					which.encoding = le.Uint32(local[4*(int(e)-len(common)/4):])
				default:
					return nil, nil, fmt.Errorf("__unwind_info encoding index %d outside its tables", e)
				}
				entries = append(entries, which)
			}
		default:
			return nil, nil, fmt.Errorf("unknown __unwind_info page kind %d", kind)
		}
		_ = first
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].function < entries[j].function })
	// Each function extends to the next entry; the index's sentinel ends the last.
	end := uint64(0)
	if n := len(index); n >= 12 {
		end = uint64(le.Uint32(index[n-12:]))
	}
	for i := range entries {
		next := end
		if i+1 < len(entries) {
			next = entries[i+1].function
		}
		if next < entries[i].function {
			return nil, nil, fmt.Errorf("__unwind_info functions are not ordered")
		}
		entries[i].length = next - entries[i].function
		entries[i].lsda = lsdas[entries[i].function]
	}
	return entries, personalities, nil
}

// unwindFrames converts compact unwind entries to DWARF appended after the
// image, adding the rebases its absolute pointers need.
func (d *DylibImage) unwindFrames() (*DylibUnwind, error) {
	if d.CompactUnwind.End == d.CompactUnwind.Start {
		return d.ehFrameOnly()
	}
	entries, personalities, err := d.compactEntries()
	if err != nil {
		return nil, err
	}
	u := &DylibUnwind{Offset: (d.Size + 15) &^ 15}
	var data []byte
	var pointers []DylibRebase
	pointer := func(target uint64) {
		pointers = append(pointers, DylibRebase{Slot: uint64(len(data)), Target: target})
		data = binary.LittleEndian.AppendUint64(data, 0)
	}
	finish := func(start int) {
		for len(data)%8 != 0 {
			data = append(data, 0)
		}
		binary.LittleEndian.PutUint32(data[start:], uint32(len(data)-start-4))
	}
	// One CIE per personality (index 0: none). Pointers are absolute, and the
	// personality is indirect through the dylib's bound slot for it.
	cies := map[uint32]int{}
	cie := func(personality uint32) (int, error) {
		if at, ok := cies[personality]; ok {
			return at, nil
		}
		start := len(data)
		data = binary.LittleEndian.AppendUint32(data, 0)
		data = binary.LittleEndian.AppendUint32(data, 0)
		ra, sp, initial := byte(30), byte(31), []byte{0x0c, 31, 0, 0x08, 30} // CFA = SP; LR holds the return address
		if d.Arch == "amd64" {
			ra, sp, initial = 16, 7, []byte{0x0c, 7, 8, 0x90, 1} // CFA = RSP+8; return address at CFA-8
		}
		_ = sp
		if personality == 0 {
			data = append(data, 1, 'z', 'R', 0, 1, 0x78, ra, 1, 0)
		} else {
			if int(personality) > len(personalities) {
				return 0, fmt.Errorf("compact unwind personality %d outside its table", personality)
			}
			data = append(data, 1, 'z', 'P', 'L', 'R', 0, 1, 0x78, ra, 11, 0x80)
			pointer(uint64(personalities[personality-1]))
			data = append(data, 0, 0)
		}
		data = append(data, initial...)
		finish(start)
		cies[personality] = start
		return start, nil
	}
	for _, e := range entries {
		mode := e.encoding & 0x0f000000
		dwarf := uint32(0x03000000)
		if d.Arch == "amd64" {
			dwarf = 0x04000000
		}
		switch {
		case e.encoding == 0 || e.length == 0:
			continue
		case mode == dwarf:
			off := uint64(e.encoding & 0xffffff)
			if d.EHFrame.Start+off >= d.EHFrame.End {
				return nil, fmt.Errorf("compact DWARF entry points outside __eh_frame")
			}
			u.FDEs = append(u.FDEs, d.EHFrame.Start+off)
			continue
		}
		var cfi []byte
		if d.Arch == "amd64" {
			cfi, err = amd64CompactCFI(e.encoding, d.Image, e.function)
		} else {
			cfi, err = arm64CompactCFI(e.encoding)
		}
		if err != nil {
			return nil, fmt.Errorf("function at %#x: %w", e.function, err)
		}
		personality := e.encoding >> 28 & 3
		c, err := cie(personality)
		if err != nil {
			return nil, err
		}
		start := len(data)
		u.FDEs = append(u.FDEs, u.Offset+uint64(start))
		data = binary.LittleEndian.AppendUint32(data, 0)
		data = binary.LittleEndian.AppendUint32(data, uint32(start+4-c))
		pointer(e.function)
		data = binary.LittleEndian.AppendUint64(data, e.length)
		if personality == 0 {
			data = append(data, 0)
		} else {
			data = append(data, 8)
			if e.encoding&0x40000000 != 0 {
				pointer(e.lsda)
			} else {
				data = binary.LittleEndian.AppendUint64(data, 0)
			}
		}
		data = append(data, cfi...)
		finish(start)
	}
	if d.EHFrame.End > d.EHFrame.Start {
		// FDEs that only __eh_frame describes still need registering; those the
		// compact table already named are not registered twice.
		named := map[uint64]bool{}
		for _, f := range u.FDEs {
			named[f] = true
		}
		own, err := d.ehFrameRecords()
		if err != nil {
			return nil, err
		}
		for _, f := range own {
			if !named[f] {
				u.FDEs = append(u.FDEs, f)
			}
		}
	}
	data = append(data, 0, 0, 0, 0)
	for _, p := range pointers {
		d.Rebases = append(d.Rebases, DylibRebase{u.Offset + p.Slot, p.Target})
	}
	sort.Slice(d.Rebases, func(i, j int) bool { return d.Rebases[i].Slot < d.Rebases[j].Slot })
	d.Image = append(append(d.Image, make([]byte, u.Offset-d.Size)...), data...)
	end := (u.Offset + uint64(len(data)) + 0x3fff) &^ 0x3fff
	d.Image = append(d.Image, make([]byte, end-uint64(len(d.Image)))...)
	d.Segments = append(d.Segments, DylibSegment{"__BAO_UNWIND", d.Size, end, 1})
	d.Size = end
	return u, nil
}

func (d *DylibImage) ehFrameOnly() (*DylibUnwind, error) {
	u := &DylibUnwind{Offset: d.Size}
	if d.EHFrame.End == d.EHFrame.Start {
		return u, nil
	}
	f, err := d.ehFrameRecords()
	u.FDEs = f
	return u, err
}

// ehFrameRecords lists the FDEs in the dylib's __eh_frame.
func (d *DylibImage) ehFrameRecords() ([]uint64, error) {
	var fdes []uint64
	b := d.Image[d.EHFrame.Start:d.EHFrame.End]
	for off := 0; off+8 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off:]))
		if n == 0 {
			break
		}
		if n == 0xffffffff || off+4+n > len(b) {
			return nil, fmt.Errorf("unsupported __eh_frame record at %#x", off)
		}
		if binary.LittleEndian.Uint32(b[off+4:]) != 0 {
			fdes = append(fdes, d.EHFrame.Start+uint64(off))
		}
		off += 4 + n
	}
	return fdes, nil
}

// arm64CompactCFI converts an arm64 FRAME or FRAMELESS encoding.
func arm64CompactCFI(encoding uint32) ([]byte, error) {
	mode := encoding & 0x0f000000
	mask := uint32(0xff000f1f)
	if mode == 0x02000000 {
		mask |= 0x00fff000
	}
	if mode != 0x02000000 && mode != 0x04000000 || encoding&^mask != 0 {
		return nil, fmt.Errorf("unsupported arm64 compact encoding %#x", encoding)
	}
	var data []byte
	next := uint64(3) // x19 at CFA-24, x20 at CFA-32, ...
	if mode == 0x04000000 {
		data = append(data, 0x0c, 29, 16, 0x9d, 2, 0x9e, 1) // CFA = FP+16; FP, LR saved
	} else {
		size := uint64(encoding>>12&0xfff) * 16
		if size < uint64(bits.OnesCount32(encoding&0xf1f))*16 {
			return nil, fmt.Errorf("frameless stack cannot hold its saved register pairs")
		}
		data = append(data, 0x0e)
		data = appendULEB(data, size)
		next = 1
	}
	for i, flag := range []uint32{1, 2, 4, 8, 16, 0x100, 0x200, 0x400, 0x800} {
		if encoding&flag == 0 {
			continue
		}
		reg := uint64(19 + 2*i)
		if i >= 5 {
			reg = uint64(72 + 2*(i-5)) // d8..d15
		}
		for j := uint64(0); j < 2; j++ {
			if reg+j < 64 {
				data = append(data, byte(0x80+reg+j))
			} else {
				data = append(data, 5)
				data = appendULEB(data, reg+j)
			}
			data = appendULEB(data, next)
			next++
		}
	}
	return data, nil
}

// amd64CompactCFI converts an x86_64 RBP_FRAME, STACK_IMMD or STACK_IND
// encoding. STACK_IND reads the stack size from the function's SUB.
func amd64CompactCFI(encoding uint32, img []byte, function uint64) ([]byte, error) {
	dwarfReg := []byte{0, 3, 12, 13, 14, 15, 6} // RBX, R12-R15, RBP
	switch mode := encoding & 0x0f000000; mode {
	case 0x01000000: // RBP_FRAME
		data := []byte{0x0c, 6, 16, 0x86, 2}
		offset := int(encoding >> 16 & 255)
		for slot := 0; slot < 5; slot++ {
			reg := encoding >> uint(3*slot) & 7
			if reg == 0 {
				continue
			}
			if reg > 6 || offset <= slot {
				return nil, fmt.Errorf("invalid compact register slot")
			}
			data = append(data, 0x80+dwarfReg[reg])
			data = appendULEB(data, uint64(2+offset-slot))
		}
		return data, nil
	case 0x02000000, 0x03000000: // STACK_IMMD, STACK_IND
		size := uint64(encoding >> 16 & 0xff)
		if mode == 0x02000000 {
			size *= 8
		} else {
			at := function + size
			if at+4 > uint64(len(img)) {
				return nil, fmt.Errorf("STACK_IND size outside the image")
			}
			size = uint64(binary.LittleEndian.Uint32(img[at:])) + 8*uint64(encoding>>13&7)
		}
		count := int(encoding >> 10 & 7)
		perm := int(encoding & 0x3ff)
		if count > 6 {
			return nil, fmt.Errorf("invalid frameless register count")
		}
		// The permutation is a factorial-base index into the remaining registers.
		var digits [6]int
		for i, radix := range [][]int{{}, {1}, {5, 1}, {20, 4, 1}, {60, 12, 3, 1}, {120, 24, 6, 2, 1}, {120, 24, 6, 2, 1, 1}}[count] {
			digits[i] = perm / radix
			perm -= digits[i] * radix
		}
		used := [7]bool{}
		data := []byte{0x0e}
		data = appendULEB(data, size)
		for i := 0; i < count; i++ {
			renumbered := 0
			for reg := 1; reg <= 6; reg++ {
				if used[reg] {
					continue
				}
				if renumbered == digits[i] {
					used[reg] = true
					data = append(data, 0x80+dwarfReg[reg])
					data = appendULEB(data, uint64(1+count-i))
					break
				}
				renumbered++
			}
		}
		return data, nil
	}
	return nil, fmt.Errorf("unsupported x86_64 compact encoding %#x", encoding)
}
