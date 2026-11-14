package translate

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// A linked dylib reaches its own code and data through PC-relative
// instructions that no longer carry relocations, its segments are contiguous,
// and arm64 macOS pages are 16 KiB: inside Go's text its data pages would share
// pages with its code. The generated package therefore loads the dylib's
// prepared image at initialization into private memory: its __TEXT in a
// MAP_JIT mapping (arm64 macOS executes only signed or JIT pages) and its
// other segments in ordinary anonymous memory at their fixed distances. Then
// rebases and binds, TLV descriptors for Bao's TLS runtime, DWARF unwind
// registration and initializers, as dyld would.

// DylibImage describes a dylib loaded by the generated package.
type DylibImage struct {
	Arch        string
	SHA256      string
	InstallName string
	// RPaths are the dylib\'s LC_RPATH entries, in order, for @rpath.
	RPaths        []string
	Size          uint64
	Segments      []DylibSegment
	Rebases       []DylibRebase
	Binds         []DylibBind
	Exports       []DylibExport
	Selected      []uint64
	TLV           *DylibTLV
	Initializers  []uint64
	Terminators   []uint64
	EHFrame       DylibRange
	CompactUnwind DylibRange
	ObjC          *DylibObjC
	Unwind        *DylibUnwind
	Image         []byte `json:"-"`
}

// DylibSegment is one segment's offset range and VM protection (1 R, 2 W, 4 X).
type DylibSegment struct {
	Name       string
	Start, End uint64
	Protect    uint32
}

// DylibRebase sets Slot to the image base plus Target.
type DylibRebase struct{ Slot, Target uint64 }

// DylibBind sets Slot to a symbol's address plus Addend. Self binds name the
// dylib's own export; others resolve with dlsym.
type DylibBind struct {
	Slot    uint64
	Name    string
	Library string `json:",omitempty"`
	Addend  int64  `json:",omitempty"`
	Weak    bool   `json:",omitempty"`
}

// DylibExport is an exported symbol, without Mach-O's leading underscore.
type DylibExport struct {
	Name     string
	Offset   uint64
	Function bool
}

// DylibRange is a half-open range of image offsets.
type DylibRange struct{ Start, End uint64 }

// DylibTLV describes thread-local variables: each descriptor is
// {thunk, key, offset} and the template spans __thread_data then __thread_bss.
type DylibTLV struct {
	Descriptors         []uint64
	Start, DataEnd, End uint64
	Alignment           uint64
}

const (
	lcDyldInfo           = 0x22
	lcDyldInfoOnly       = 0x80000022
	lcDyldExportsTrie    = 0x80000033
	lcDyldChainedFixups  = 0x80000034
	lcLoadDylib          = 0xc
	lcLoadWeakDylib      = 0x80000018
	lcReexportDylib      = 0x8000001f
	lcLoadUpwardDylib    = 0x80000023
	lcIDDylib            = 0xd
	lcRPath              = 0x8000001c
	sThreadLocalRegular  = 0x11
	sThreadLocalZerofill = 0x12
	sThreadLocalVars     = 0x13
	sModInitFuncPointers = 0x9
	sModTermFuncPointers = 0xa
	sInitFuncOffsets     = 0x16
	dylibMaxImage        = 512 << 20
)

// IsDylib reports whether input is a Mach-O dynamic library.
func IsDylib(input []byte) bool {
	f, err := macho.NewFile(bytes.NewReader(input))
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Type == macho.TypeDylib
}

func parseDylib(input []byte, symbols []string) (*DylibImage, string, error) {
	f, err := macho.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	if f.Type != macho.TypeDylib || f.Magic != macho.Magic64 {
		return nil, "", fmt.Errorf("requires a 64-bit Mach-O dynamic library")
	}
	arch := ""
	switch {
	case f.Cpu == macho.CpuArm64 && f.SubCpu&0xff == 0:
		arch = "arm64"
	case f.Cpu == macho.CpuAmd64:
		arch = "amd64"
	default:
		return nil, "", fmt.Errorf("unsupported dylib CPU %v/%#x (arm64e is unsupported)", f.Cpu, f.SubCpu)
	}
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, "__swift5_") {
			return nil, "", fmt.Errorf("Swift dylibs need runtime registration Bao does not provide yet (%s,%s)", s.Seg, s.Name)
		}
	}
	d := &DylibImage{Arch: arch}
	sum := sha256.Sum256(input)
	d.SHA256 = fmt.Sprintf("%x", sum)
	var base uint64
	var libraries []string
	var segments []*macho.Segment
	var chained, info, trie []byte
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := binary.LittleEndian.Uint32(raw)
		switch v := l.(type) {
		case *macho.Segment:
			if v.Name == "__PAGEZERO" {
				return nil, "", fmt.Errorf("dylib has __PAGEZERO; is it an executable?")
			}
			segments = append(segments, v)
			continue
		case *macho.Dylib:
			if cmd != lcIDDylib {
				libraries = append(libraries, v.Name)
			} else {
				d.InstallName = v.Name
			}
			continue
		}
		data := func() ([]byte, error) {
			off, size := binary.LittleEndian.Uint32(raw[8:]), binary.LittleEndian.Uint32(raw[12:])
			if uint64(off)+uint64(size) > uint64(len(input)) {
				return nil, fmt.Errorf("dylib linkedit data outside the file")
			}
			return input[off : off+size], nil
		}
		switch cmd {
		case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib:
			// debug/macho decodes only LC_LOAD_DYLIB; keep ordinals aligned.
			if len(raw) >= 24 {
				off := binary.LittleEndian.Uint32(raw[8:])
				name := raw[off:]
				if i := bytes.IndexByte(name, 0); i >= 0 {
					name = name[:i]
				}
				libraries = append(libraries, string(name))
			}
		case lcRPath:
			if len(raw) >= 12 {
				off := binary.LittleEndian.Uint32(raw[8:])
				if int(off) < len(raw) {
					name := raw[off:]
					if i := bytes.IndexByte(name, 0); i >= 0 {
						name = name[:i]
					}
					d.RPaths = append(d.RPaths, string(name))
				}
			}
		case lcDyldChainedFixups:
			if chained, err = data(); err != nil {
				return nil, "", err
			}
		case lcDyldExportsTrie:
			if trie, err = data(); err != nil {
				return nil, "", err
			}
		case lcDyldInfo, lcDyldInfoOnly:
			if len(raw) < 48 {
				return nil, "", fmt.Errorf("short LC_DYLD_INFO")
			}
			info = raw
			if off, size := binary.LittleEndian.Uint32(raw[40:]), binary.LittleEndian.Uint32(raw[44:]); size != 0 {
				if uint64(off)+uint64(size) > uint64(len(input)) {
					return nil, "", fmt.Errorf("dylib export trie outside the file")
				}
				trie = input[off : off+size]
			}
		}
	}
	if len(segments) == 0 || segments[0].Name != "__TEXT" || segments[0].Offset != 0 {
		return nil, "", fmt.Errorf("dylib must start with a __TEXT segment that maps its header")
	}
	base = segments[0].Addr
	for _, s := range segments {
		if s.Name == "__LINKEDIT" {
			continue
		}
		if s.Addr < base || s.Addr+s.Memsz > base+dylibMaxImage || s.Filesz > s.Memsz || s.Offset+s.Filesz > uint64(len(input)) {
			return nil, "", fmt.Errorf("dylib segment %s exceeds translation bounds", s.Name)
		}
		if s.Prot&2 != 0 && s.Prot&4 != 0 {
			return nil, "", fmt.Errorf("writable executable dylib segment %s is unsupported", s.Name)
		}
		d.Size = max(d.Size, s.Addr-base+s.Memsz)
		d.Segments = append(d.Segments, DylibSegment{s.Name, s.Addr - base, s.Addr - base + s.Memsz, uint32(s.Prot)})
	}
	img := make([]byte, d.Size)
	for _, s := range segments {
		if s.Name != "__LINKEDIT" {
			copy(img[s.Addr-base:], input[s.Offset:s.Offset+s.Filesz])
		}
	}
	segmentAt := func(off uint64) *DylibSegment {
		for i := range d.Segments {
			if off >= d.Segments[i].Start && off < d.Segments[i].End {
				return &d.Segments[i]
			}
		}
		return nil
	}
	slot := func(off uint64) error {
		s := segmentAt(off)
		if s == nil || off+8 > s.End || s.Protect&4 != 0 {
			return fmt.Errorf("dylib fixup at %#x is outside its data segments", off)
		}
		return nil
	}
	library := func(ordinal int) string {
		if ordinal > 0 && ordinal <= len(libraries) {
			return libraries[ordinal-1]
		}
		return ""
	}

	switch {
	case chained != nil:
		if err := d.chainedFixups(chained, img, base, slot, library); err != nil {
			return nil, "", err
		}
	case info != nil:
		if err := d.dyldInfo(input, info, img, segments, base, slot, library); err != nil {
			return nil, "", err
		}
	}
	sort.Slice(d.Rebases, func(i, j int) bool { return d.Rebases[i].Slot < d.Rebases[j].Slot })
	sort.Slice(d.Binds, func(i, j int) bool { return d.Binds[i].Slot < d.Binds[j].Slot })
	seen := map[uint64]bool{}
	for _, r := range d.Rebases {
		if seen[r.Slot] || r.Target > d.Size {
			return nil, "", fmt.Errorf("invalid or duplicate dylib rebase at %#x", r.Slot)
		}
		seen[r.Slot] = true
	}
	for _, b := range d.Binds {
		if seen[b.Slot] {
			return nil, "", fmt.Errorf("duplicate dylib fixup at %#x", b.Slot)
		}
		seen[b.Slot] = true
	}

	if trie != nil {
		if err := d.exportTrie(trie, segmentAt); err != nil {
			return nil, "", err
		}
	}
	sort.Slice(d.Exports, func(i, j int) bool { return d.Exports[i].Name < d.Exports[j].Name })
	for _, name := range symbols {
		i := sort.Search(len(d.Exports), func(i int) bool { return d.Exports[i].Name >= name })
		if i == len(d.Exports) || d.Exports[i].Name != name || !d.Exports[i].Function {
			return nil, "", fmt.Errorf("selected export %q is not a function the dylib exports", name)
		}
		d.Selected = append(d.Selected, d.Exports[i].Offset)
	}

	// Sections that dyld interprets.
	for _, s := range f.Sections {
		if s.Seg == "__LINKEDIT" || s.Size == 0 {
			continue
		}
		off := s.Addr - base
		if off+s.Size > d.Size {
			return nil, "", fmt.Errorf("dylib section %s,%s outside the image", s.Seg, s.Name)
		}
		switch s.Flags & 0xff {
		case sThreadLocalVars:
			if s.Size%24 != 0 {
				return nil, "", fmt.Errorf("malformed __thread_vars")
			}
			if d.TLV == nil {
				d.TLV = &DylibTLV{}
			}
			for at := off; at < off+s.Size; at += 24 {
				d.TLV.Descriptors = append(d.TLV.Descriptors, at)
			}
		case sThreadLocalRegular, sThreadLocalZerofill:
			if d.TLV == nil {
				d.TLV = &DylibTLV{}
			}
			t := d.TLV
			if t.End == 0 {
				t.Start = off
			}
			t.Start = min(t.Start, off)
			t.End = max(t.End, off+s.Size)
			if s.Flags&0xff == sThreadLocalRegular {
				t.DataEnd = max(t.DataEnd, off+s.Size)
			}
			t.Alignment = max(t.Alignment, uint64(1)<<s.Align)
		case sModInitFuncPointers, sModTermFuncPointers:
			if s.Size%8 != 0 {
				return nil, "", fmt.Errorf("malformed %s", s.Name)
			}
			for at := off; at < off+s.Size; at += 8 {
				target, ok := d.rebaseTarget(at)
				if !ok {
					return nil, "", fmt.Errorf("%s entry at %#x is not a rebased pointer", s.Name, at)
				}
				if s.Flags&0xff == sModInitFuncPointers {
					d.Initializers = append(d.Initializers, target)
				} else {
					d.Terminators = append(d.Terminators, target)
				}
			}
		case sInitFuncOffsets:
			if s.Size%4 != 0 {
				return nil, "", fmt.Errorf("malformed __init_offsets")
			}
			for at := off; at < off+s.Size; at += 4 {
				d.Initializers = append(d.Initializers, uint64(binary.LittleEndian.Uint32(img[at:])))
			}
		}
		switch {
		case s.Seg == "__TEXT" && s.Name == "__eh_frame":
			d.EHFrame = DylibRange{off, off + s.Size}
		case s.Seg == "__TEXT" && s.Name == "__unwind_info":
			d.CompactUnwind = DylibRange{off, off + s.Size}
		case strings.HasPrefix(s.Name, "__objc_"):
			if d.ObjC == nil {
				d.ObjC = &DylibObjC{}
			}
			if err := d.ObjC.section(s.Name, DylibRange{off, off + s.Size}); err != nil {
				return nil, "", err
			}
		}
	}
	for _, target := range append(append([]uint64(nil), d.Initializers...), d.Terminators...) {
		if s := segmentAt(target); s == nil || s.Protect&4 == 0 {
			return nil, "", fmt.Errorf("dylib initializer %#x is outside code", target)
		}
	}
	if t := d.TLV; t != nil {
		if len(t.Descriptors) == 0 || t.End == 0 {
			return nil, "", fmt.Errorf("dylib thread-local variables need both descriptors and a template")
		}
		if t.DataEnd == 0 {
			t.DataEnd = t.Start
		}
		for _, at := range t.Descriptors {
			// The thunk word binds _tlv_bootstrap; Bao's thunk replaces it.
			d.dropFixup(at)
			d.dropFixup(at + 8)
			if off := binary.LittleEndian.Uint64(img[at+16:]); off >= t.End-t.Start {
				return nil, "", fmt.Errorf("TLV descriptor at %#x is outside the template", at)
			}
		}
	}
	d.Image = img
	return d, arch, nil
}

func (d *DylibImage) rebaseTarget(slot uint64) (uint64, bool) {
	i := sort.Search(len(d.Rebases), func(i int) bool { return d.Rebases[i].Slot >= slot })
	if i < len(d.Rebases) && d.Rebases[i].Slot == slot {
		return d.Rebases[i].Target, true
	}
	return 0, false
}

func (d *DylibImage) dropFixup(slot uint64) {
	for i, r := range d.Rebases {
		if r.Slot == slot {
			d.Rebases = append(d.Rebases[:i], d.Rebases[i+1:]...)
			return
		}
	}
	for i, b := range d.Binds {
		if b.Slot == slot {
			d.Binds = append(d.Binds[:i], d.Binds[i+1:]...)
			return
		}
	}
}

func uleb(b []byte, p *int) (uint64, error) {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		if *p >= len(b) || shift > 63 {
			return 0, fmt.Errorf("truncated ULEB128")
		}
		c := b[*p]
		*p++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
	}
}

func sleb(b []byte, p *int) (int64, error) {
	var v int64
	shift := uint(0)
	for {
		if *p >= len(b) || shift > 63 {
			return 0, fmt.Errorf("truncated SLEB128")
		}
		c := b[*p]
		*p++
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, nil
		}
	}
}

func cstr(b []byte, p int) (string, error) {
	if p < 0 || p >= len(b) {
		return "", fmt.Errorf("dylib string outside its table")
	}
	end := bytes.IndexByte(b[p:], 0)
	if end < 0 {
		return "", fmt.Errorf("unterminated dylib string")
	}
	return string(b[p : p+end]), nil
}

// cName strips Mach-O's C symbol underscore.
func cName(s string) string { return strings.TrimPrefix(s, "_") }

// chainedFixups walks LC_DYLD_CHAINED_FIXUPS for the userland 64-bit pointer
// formats (DYLD_CHAINED_PTR_64 and DYLD_CHAINED_PTR_64_OFFSET).
func (d *DylibImage) chainedFixups(b, img []byte, base uint64, slot func(uint64) error, library func(int) string) error {
	if len(b) < 28 {
		return fmt.Errorf("short chained fixups header")
	}
	le := binary.LittleEndian
	startsOff, importsOff, symbolsOff, count, importFormat := le.Uint32(b[4:]), le.Uint32(b[8:]), le.Uint32(b[12:]), le.Uint32(b[16:]), le.Uint32(b[20:])
	if le.Uint32(b[24:]) != 0 {
		return fmt.Errorf("compressed chained fixup symbols are unsupported")
	}
	type imp struct {
		name    string
		library string
		addend  int64
		weak    bool
	}
	imports := make([]imp, count)
	for i := uint32(0); i < count; i++ {
		var ordinal int
		var weak bool
		var name uint32
		var addend int64
		switch importFormat {
		case 1, 2:
			size := uint32(4)
			if importFormat == 2 {
				size = 8
			}
			at := importsOff + i*size
			if uint64(at)+uint64(size) > uint64(len(b)) {
				return fmt.Errorf("chained imports outside the table")
			}
			v := le.Uint32(b[at:])
			ordinal, weak, name = int(int8(v)), v>>8&1 != 0, v>>9
			if importFormat == 2 {
				addend = int64(int32(le.Uint32(b[at+4:])))
			}
		case 3:
			at := importsOff + i*16
			if uint64(at)+16 > uint64(len(b)) {
				return fmt.Errorf("chained imports outside the table")
			}
			ordinal, weak, name = int(int16(le.Uint16(b[at:]))), le.Uint16(b[at+2:])&1 != 0, le.Uint32(b[at+4:])
			addend = int64(le.Uint64(b[at+8:]))
		default:
			return fmt.Errorf("unsupported chained import format %d", importFormat)
		}
		s, err := cstr(b, int(symbolsOff+name))
		if err != nil {
			return err
		}
		imports[i] = imp{cName(s), library(ordinal), addend, weak}
	}
	if uint64(startsOff)+4 > uint64(len(b)) {
		return fmt.Errorf("chained starts outside the table")
	}
	segs := le.Uint32(b[startsOff:])
	for si := uint32(0); si < segs; si++ {
		at := startsOff + 4 + 4*si
		if uint64(at)+4 > uint64(len(b)) {
			return fmt.Errorf("chained starts outside the table")
		}
		off := le.Uint32(b[at:])
		if off == 0 {
			continue
		}
		s := startsOff + off
		if uint64(s)+22 > uint64(len(b)) {
			return fmt.Errorf("chained segment starts outside the table")
		}
		pageSize, format, segOffset, pages := uint64(le.Uint16(b[s+4:])), le.Uint16(b[s+6:]), le.Uint64(b[s+8:]), le.Uint16(b[s+20:])
		if format != 2 && format != 6 {
			return fmt.Errorf("unsupported chained pointer format %d (arm64e and 32-bit formats are unsupported)", format)
		}
		for page := uint32(0); page < uint32(pages); page++ {
			if uint64(s)+22+2*uint64(page)+2 > uint64(len(b)) {
				return fmt.Errorf("chained page starts outside the table")
			}
			start := le.Uint16(b[s+22+2*page:])
			if start == 0xffff {
				continue
			}
			if start&0x8000 != 0 {
				return fmt.Errorf("multi-start chained pages are unsupported")
			}
			for p := segOffset + uint64(page)*pageSize + uint64(start); ; {
				if err := slot(p); err != nil {
					return err
				}
				v := le.Uint64(img[p:])
				next := v >> 51 & 0xfff
				if v>>63 != 0 {
					ordinal := v & 0xffffff
					if ordinal >= uint64(len(imports)) {
						return fmt.Errorf("chained bind at %#x names import %d of %d", p, ordinal, len(imports))
					}
					im := imports[ordinal]
					d.Binds = append(d.Binds, DylibBind{Slot: p, Name: im.name, Library: im.library, Addend: im.addend + int64(int8(v>>24)), Weak: im.weak})
				} else {
					target, high := v&0xfffffffff, v>>36&0xff
					if format == 2 {
						target -= base
					}
					if high != 0 {
						return fmt.Errorf("tagged chained rebase at %#x is unsupported", p)
					}
					d.Rebases = append(d.Rebases, DylibRebase{p, target})
				}
				binary.LittleEndian.PutUint64(img[p:], 0)
				if next == 0 {
					break
				}
				p += next * 4
			}
		}
	}
	return nil
}

// dyldInfo interprets LC_DYLD_INFO rebase, bind, weak bind and lazy bind
// opcodes. Lazy binds are bound eagerly.
func (d *DylibImage) dyldInfo(input, raw, img []byte, segments []*macho.Segment, base uint64, slot func(uint64) error, library func(int) string) error {
	le := binary.LittleEndian
	table := func(at int) ([]byte, error) {
		off, size := le.Uint32(raw[at:]), le.Uint32(raw[at+4:])
		if uint64(off)+uint64(size) > uint64(len(input)) {
			return nil, fmt.Errorf("dyld info outside the file")
		}
		return input[off : off+size], nil
	}
	segAddr := func(i uint64, off uint64) (uint64, error) {
		if i >= uint64(len(segments)) {
			return 0, fmt.Errorf("dyld info names segment %d", i)
		}
		return segments[i].Addr - base + off, nil
	}
	rebases, err := table(8)
	if err != nil {
		return err
	}
	var at uint64
	for p := 0; p < len(rebases); {
		op, imm := rebases[p]&0xf0, uint64(rebases[p]&0x0f)
		p++
		times, skip := uint64(0), uint64(0)
		switch op {
		case 0x00: // DONE
			p = len(rebases)
			continue
		case 0x10: // SET_TYPE_IMM
			if imm != 1 {
				return fmt.Errorf("unsupported rebase type %d", imm)
			}
			continue
		case 0x20: // SET_SEGMENT_AND_OFFSET_ULEB
			off, err := uleb(rebases, &p)
			if err != nil {
				return err
			}
			if at, err = segAddr(imm, off); err != nil {
				return err
			}
			continue
		case 0x30: // ADD_ADDR_ULEB
			v, err := uleb(rebases, &p)
			if err != nil {
				return err
			}
			at += v
			continue
		case 0x40: // ADD_ADDR_IMM_SCALED
			at += imm * 8
			continue
		case 0x50: // DO_REBASE_IMM_TIMES
			times = imm
		case 0x60: // DO_REBASE_ULEB_TIMES
			if times, err = uleb(rebases, &p); err != nil {
				return err
			}
		case 0x70: // DO_REBASE_ADD_ADDR_ULEB
			times = 1
			if skip, err = uleb(rebases, &p); err != nil {
				return err
			}
		case 0x80: // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
			if times, err = uleb(rebases, &p); err != nil {
				return err
			}
			if skip, err = uleb(rebases, &p); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown rebase opcode %#x", op)
		}
		if times > 1<<24 {
			return fmt.Errorf("rebase count exceeds translation bounds")
		}
		for ; times > 0; times-- {
			if err := slot(at); err != nil {
				return err
			}
			// The slot holds the target's unslid address.
			d.Rebases = append(d.Rebases, DylibRebase{at, le.Uint64(img[at:]) - base})
			le.PutUint64(img[at:], 0)
			at += 8 + skip
		}
	}
	for kind, off := range []int{16, 24, 32} { // bind, weak bind, lazy bind
		ops, err := table(off)
		if err != nil {
			return err
		}
		var name string
		var ordinal int
		var addend int64
		var weak bool
		for p := 0; p < len(ops); {
			op, imm := ops[p]&0xf0, ops[p]&0x0f
			p++
			times, skip := uint64(0), uint64(0)
			switch op {
			case 0x00: // DONE ends a lazy bind record only
				if kind != 2 {
					p = len(ops)
				}
				continue
			case 0x10: // SET_DYLIB_ORDINAL_IMM
				ordinal = int(imm)
				continue
			case 0x20: // SET_DYLIB_ORDINAL_ULEB
				v, err := uleb(ops, &p)
				if err != nil {
					return err
				}
				ordinal = int(v)
				continue
			case 0x30: // SET_DYLIB_SPECIAL_IMM
				ordinal = -int(16 - int(imm)&15)
				if imm == 0 {
					ordinal = 0
				}
				continue
			case 0x40: // SET_SYMBOL_TRAILING_FLAGS_IMM
				if name, err = cstr(ops, p); err != nil {
					return err
				}
				p += len(name) + 1
				weak = imm&1 != 0
				name = cName(name)
				continue
			case 0x50: // SET_TYPE_IMM
				if imm != 1 {
					return fmt.Errorf("unsupported bind type %d", imm)
				}
				continue
			case 0x60: // SET_ADDEND_SLEB
				if addend, err = sleb(ops, &p); err != nil {
					return err
				}
				continue
			case 0x70: // SET_SEGMENT_AND_OFFSET_ULEB
				o, err := uleb(ops, &p)
				if err != nil {
					return err
				}
				if at, err = segAddr(uint64(imm), o); err != nil {
					return err
				}
				continue
			case 0x80: // ADD_ADDR_ULEB
				v, err := uleb(ops, &p)
				if err != nil {
					return err
				}
				at += v
				continue
			case 0x90: // DO_BIND
				times = 1
			case 0xa0: // DO_BIND_ADD_ADDR_ULEB
				times = 1
				if skip, err = uleb(ops, &p); err != nil {
					return err
				}
			case 0xb0: // DO_BIND_ADD_ADDR_IMM_SCALED
				times, skip = 1, uint64(imm)*8
			case 0xc0: // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
				if times, err = uleb(ops, &p); err != nil {
					return err
				}
				if skip, err = uleb(ops, &p); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown bind opcode %#x", op)
			}
			if times > 1<<24 {
				return fmt.Errorf("bind count exceeds translation bounds")
			}
			for ; times > 0; times-- {
				if err := slot(at); err != nil {
					return err
				}
				// Weak binds coalesce weak definitions across images; a dylib
				// linked into one executable keeps its own.
				if kind == 1 {
					at += 8 + skip
					continue
				}
				d.dropFixup(at)
				d.Binds = append(d.Binds, DylibBind{Slot: at, Name: name, Library: library(ordinal), Addend: addend, Weak: weak})
				le.PutUint64(img[at:], 0)
				at += 8 + skip
			}
		}
	}
	return nil
}

// exportTrie reads the export trie; re-exports and stub resolvers have no
// address in this image and are skipped.
func (d *DylibImage) exportTrie(trie []byte, segmentAt func(uint64) *DylibSegment) error {
	type node struct {
		at     uint64
		prefix string
	}
	stack := []node{{0, ""}}
	visited := map[uint64]bool{}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n.at] || n.at >= uint64(len(trie)) {
			return fmt.Errorf("malformed dylib export trie")
		}
		visited[n.at] = true
		p := int(n.at)
		size, err := uleb(trie, &p)
		if err != nil {
			return err
		}
		children := p + int(size)
		if size != 0 {
			flags, err := uleb(trie, &p)
			if err != nil {
				return err
			}
			if flags&0x18 == 0 && flags&3 == 0 { // regular, neither re-export nor resolver
				off, err := uleb(trie, &p)
				if err != nil {
					return err
				}
				if s := segmentAt(off); s != nil {
					d.Exports = append(d.Exports, DylibExport{cName(n.prefix), off, s.Protect&4 != 0})
				}
			}
		}
		if children >= len(trie) {
			return fmt.Errorf("malformed dylib export trie")
		}
		p = children
		count := int(trie[p])
		p++
		for i := 0; i < count; i++ {
			edge, err := cstr(trie, p)
			if err != nil {
				return err
			}
			p += len(edge) + 1
			child, err := uleb(trie, &p)
			if err != nil {
				return err
			}
			stack = append(stack, node{child, n.prefix + edge})
		}
	}
	return nil
}

// PrepareDylib plans a dylib for loading by the generated package. The
// returned anchor object carries the dylib's TLV template, at the offsets its
// descriptors use, through the ordinary translation, which links Bao's TLS
// runtime.
func PrepareDylib(input []byte, symbols []string) (*DylibImage, Object, error) {
	d, arch, err := parseDylib(input, symbols)
	if err != nil {
		return nil, Object{}, err
	}
	if d.Unwind, err = d.unwindFrames(); err != nil {
		return nil, Object{}, err
	}
	return d, dylibAnchor(arch, d), nil
}

// dylibAnchor builds the object that carries the dylib's prepared image as
// one 16 KiB-aligned read-only section. Go's Darwin linker places read-only
// host sections in __TEXT,__rodata, inside the executable and signed __TEXT
// segment, so the image's code runs where it is linked; the image needs no
// link-time relocations, and its data pages are made writable at load. Only
// .text alignment beyond 4 KiB triggers the runtime.text misplacement of the
// 2026-11-14 text alignment entry. The object also links Bao's TLS runtime.
func dylibAnchor(arch string, d *DylibImage) Object {
	cpu, ret := macho.CpuArm64, []byte{0xc0, 0x03, 0x5f, 0xd6}
	if arch == "amd64" {
		cpu, ret = macho.CpuAmd64, []byte{0xc3, 0xcc, 0xcc, 0xcc}
	}
	sections := []anchorSection{
		{seg: "__TEXT", name: "__text", flags: 0x80000400, data: ret, align: 2},
		{seg: "__TEXT", name: "__bao_image", data: d.Image, align: 14},
	}
	syms := []anchorSymbol{
		{name: "_bao_dylib_anchor", section: 1, global: true},
		{name: "_" + d.BaseSymbol(), section: 2, global: true},
	}
	return Object{Name: "bao-dylib-anchor.o", Data: machoObject(cpu, sections, syms)}
}

// BaseSymbol names the image's first byte; the dylib's digest keeps it
// distinct for each dylib.
func (d *DylibImage) BaseSymbol() string { return "bao_dylib_" + d.SHA256[:16] + "_image" }

type anchorSection struct {
	seg, name string
	flags     uint32
	data      []byte
	zero      uint64
	align     uint8
	relocs    []anchorReloc
}

// anchorReloc is an 8-byte absolute relocation at off against symbol sym.
type anchorReloc struct{ off, sym uint32 }

type anchorSymbol struct {
	name    string
	section uint8 // 1-based; 0 for undefined
	global  bool
	extern  bool
}

// machoObject writes a minimal MH_OBJECT. Sections follow each other at their
// alignments; a symbol sits at the start of its section.
func machoObject(cpu macho.Cpu, sections []anchorSection, symbols []anchorSymbol) []byte {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	cmdsize := 72 + 80*len(sections) + 24
	addrs := make([]uint64, len(sections))
	var size, fileSize uint64
	for i, s := range sections {
		size = (size + 1<<s.align - 1) &^ (1<<s.align - 1)
		addrs[i] = size
		size += uint64(len(s.data)) + s.zero
		if s.zero == 0 {
			fileSize = size
		}
	}
	dataStart := uint64(32 + cmdsize)
	nrelocs := 0
	for _, s := range sections {
		nrelocs += len(s.relocs)
	}
	subtype := uint32(0)
	if cpu == macho.CpuAmd64 {
		subtype = 3 // CPU_SUBTYPE_X86_64_ALL
	}
	w([8]uint32{macho.Magic64, uint32(cpu), subtype, uint32(macho.TypeObj), 2, uint32(cmdsize), 0, 0})
	w([2]uint32{uint32(macho.LoadCmdSegment64), uint32(72 + 80*len(sections))})
	w([16]byte{})
	w([4]uint64{0, size, dataStart, fileSize})
	w([4]uint32{7, 7, uint32(len(sections)), 0})
	relocOff := dataStart + fileSize
	for i, s := range sections {
		var name, seg [16]byte
		copy(name[:], s.name)
		copy(seg[:], s.seg)
		w(name)
		w(seg)
		w([2]uint64{addrs[i], uint64(len(s.data)) + s.zero})
		offset := uint32(dataStart + addrs[i])
		if s.zero != 0 {
			offset = 0
		}
		w([8]uint32{offset, uint32(s.align), uint32(relocOff), uint32(len(s.relocs)), s.flags, 0, 0, 0})
		relocOff += uint64(8 * len(s.relocs))
	}
	strtab := []byte{0}
	symoff := dataStart + fileSize + uint64(8*nrelocs)
	w([6]uint32{uint32(macho.LoadCmdSymtab), 24, uint32(symoff), uint32(len(symbols)), uint32(symoff) + uint32(16*len(symbols)), 0})
	stroffAt := b.Len() - 4
	for i, s := range sections {
		for uint64(b.Len()) < dataStart+addrs[i] && s.zero == 0 {
			b.WriteByte(0)
		}
		b.Write(s.data)
	}
	for uint64(b.Len()) < dataStart+fileSize {
		b.WriteByte(0)
	}
	for _, s := range sections {
		for _, r := range s.relocs {
			w([2]uint32{r.off, r.sym | 3<<25 | 1<<27}) // extern, 8 bytes, unsigned
		}
	}
	for _, s := range symbols {
		typ, sect, value := uint8(0x1), uint8(0), uint64(0) // N_UNDF|N_EXT
		if s.section != 0 {
			typ, sect, value = 0xe, s.section, addrs[s.section-1] // N_SECT
			if s.global {
				typ |= 1
			}
		}
		w(uint32(len(strtab)))
		w(typ)
		w(sect)
		w(uint16(0))
		w(value)
		strtab = append(append(strtab, s.name...), 0)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint32(out[stroffAt-4:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[stroffAt:], uint32(len(strtab)))
	return append(out, strtab...)
}

// DylibObjC locates the Objective-C metadata the generated loader registers
// with libobjc. dyld normally hands an image to libobjc; this image is part of
// the executable, so the loader uniques selectors, reads classes with the
// public objc_readClassPair (which exists for images dyld did not load),
// registers protocols, attaches categories and runs +load itself.
type DylibObjC struct {
	ImageInfo   uint64
	SelRefs     DylibRange
	Classes     DylibRange // __objc_classlist
	LoadClasses DylibRange // __objc_nlclslist: classes with +load
	Categories  DylibRange // __objc_catlist
	LoadCats    DylibRange // __objc_nlcatlist
	Protocols   DylibRange // __objc_protolist
	ProtoRefs   DylibRange
}

func (o *DylibObjC) section(name string, r DylibRange) error {
	switch name {
	case "__objc_imageinfo":
		if r.End-r.Start < 8 {
			return fmt.Errorf("short __objc_imageinfo")
		}
		o.ImageInfo = r.Start
		return nil
	case "__objc_selrefs":
		o.SelRefs = r
	case "__objc_classlist":
		o.Classes = r
	case "__objc_nlclslist":
		o.LoadClasses = r
	case "__objc_catlist", "__objc_catlist2":
		if o.Categories.End != 0 {
			return fmt.Errorf("multiple Objective-C category lists are unsupported")
		}
		o.Categories = r
	case "__objc_nlcatlist":
		o.LoadCats = r
	case "__objc_protolist":
		o.Protocols = r
	case "__objc_protorefs":
		o.ProtoRefs = r
	default:
		// Strings, method lists, class data and references are reached
		// through the lists above or need no registration.
		return nil
	}
	if (r.End-r.Start)%8 != 0 {
		return fmt.Errorf("Objective-C list %s is not a pointer array", name)
	}
	return nil
}
