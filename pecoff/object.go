// Package pecoff prepares bounded Windows COFF objects for Go's internal linker.
package pecoff

import (
	"bytes"
	"debug/dwarf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type section struct {
	name        string
	flags, size uint32
	data        []byte
	relocs      []pe.Reloc
}
type object struct {
	machine   uint16
	timestamp uint32
	sections  []section
	symbols   []pe.COFFSymbol
	names     []string
}

const imageSCNLinkRemove = 0x00000800 // IMAGE_SCN_LNK_REMOVE

func Machine(input []byte) (uint16, error) {
	if len(input) < 20 || input[0] == 'M' && input[1] == 'Z' {
		return 0, fmt.Errorf("requires an ordinary COFF relocatable object, not a PE image/import record")
	}
	m := binary.LittleEndian.Uint16(input)
	if m != pe.IMAGE_FILE_MACHINE_AMD64 && m != pe.IMAGE_FILE_MACHINE_ARM64 {
		return 0, fmt.Errorf("unsupported COFF machine %#x", m)
	}
	if binary.LittleEndian.Uint16(input[16:]) != 0 || int(binary.LittleEndian.Uint16(input[2:])) > (len(input)-20)/40 || uint64(binary.LittleEndian.Uint32(input[12:])) > uint64(len(input))/18 {
		return 0, fmt.Errorf("invalid COFF header bounds")
	}
	return m, nil
}

func parse(input []byte) (*object, error) {
	m, err := Machine(input)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	o := &object{machine: m, timestamp: f.TimeDateStamp, symbols: append([]pe.COFFSymbol(nil), f.COFFSymbols...), names: make([]string, len(f.COFFSymbols))}
	for i := 0; i < len(o.symbols); {
		s := o.symbols[i]
		if i+int(s.NumberOfAuxSymbols) >= len(o.symbols) {
			return nil, fmt.Errorf("truncated COFF auxiliary symbols")
		}
		o.names[i], err = s.FullName(f.StringTable)
		if err != nil {
			return nil, err
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	for _, s := range f.Sections {
		if s.Name == ".idata" || strings.HasPrefix(s.Name, ".idata$") {
			return nil, fmt.Errorf("COFF import-library thunk is not an ordinary native definition")
		}
		if s.VirtualAddress != 0 || s.NumberOfRelocations == 0xffff || s.Characteristics&0x01000000 != 0 {
			return nil, fmt.Errorf("unsupported COFF section layout %s", s.Name)
		}
		var data []byte
		if s.Characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0 {
			data, err = s.Data()
			if err != nil {
				return nil, err
			}
		}
		o.sections = append(o.sections, section{s.Name, s.Characteristics, s.Size, append([]byte(nil), data...), append([]pe.Reloc(nil), s.Relocs...)})
	}
	return o, nil
}

func debugSection(s string) bool {
	return strings.HasPrefix(s, ".debug") || strings.HasPrefix(s, ".zdebug") || s == ".llvm_addrsig" || s == ".chks64" || s == ".voltbl"
}

// StripDebug removes debug payloads, file records and their unreferenced symbols.
// Section numbering stays stable for associative COMDAT metadata.
func StripDebug(input []byte) ([]byte, int, error) {
	b, r, err := strip(input, true)
	return b, r.debug + r.bitcode, err
}

func bitcodeSection(s string) bool {
	return s == ".llvmbc" || s == ".llvmcmd"
}

type stripped struct {
	debug, bitcode int
	bitcodeBytes   uint64
}

func strip(input []byte, debug bool) ([]byte, stripped, error) {
	var r stripped
	o, err := parse(input)
	if err != nil {
		return nil, r, err
	}
	removed := map[int16]bool{}
	for i, s := range o.sections {
		// Linker-remove payloads, including Rust's embedded LLVM bitcode and
		// its command line, have no runtime address. They are always dropped.
		switch {
		case bitcodeSection(s.name):
			r.bitcode++
			r.bitcodeBytes += uint64(s.size)
		case debug && debugSection(s.name) || s.flags&imageSCNLinkRemove != 0:
			r.debug++
		default:
			continue
		}
		removed[int16(i+1)] = true
		o.sections[i] = section{name: ".bao.drop", flags: pe.IMAGE_SCN_MEM_DISCARDABLE}
	}
	remap := map[uint32]uint32{}
	var syms []pe.COFFSymbol
	var names []string
	for i := 0; i < len(o.symbols); {
		s := o.symbols[i]
		n := int(s.NumberOfAuxSymbols) + 1
		compilerID := s.StorageClass == 3 && s.SectionNumber == -1 && (o.names[i] == "@comp.id" || o.names[i] == "@vol.md")
		if !removed[s.SectionNumber] && s.StorageClass != 103 && !compilerID {
			remap[uint32(i)] = uint32(len(syms))
			syms = append(syms, o.symbols[i:i+n]...)
			names = append(names, o.names[i:i+n]...)
		}
		i += n
	}
	for si := range o.sections {
		for ri := range o.sections[si].relocs {
			rel := &o.sections[si].relocs[ri]
			idx, ok := remap[rel.SymbolTableIndex]
			if !ok {
				return nil, r, fmt.Errorf("retained COFF relocation in %s references a discarded debug or LLVM bitcode symbol", o.sections[si].name)
			}
			rel.SymbolTableIndex = idx
		}
	}
	o.symbols, o.names = syms, names
	b, err := o.encode()
	return b, r, err
}

// Go's COFF reader cannot represent associative COMDATs or repeated section
// names. COMDAT selection has already discarded losing groups; concatenate
// only the surviving native SEH tables.
func (o *object) normalizeSections() error {
	for _, name := range []string{".pdata", ".xdata"} {
		first := -1
		for i := range o.sections {
			if !(o.sections[i].name == name || strings.HasPrefix(o.sections[i].name, name+".") || strings.HasPrefix(o.sections[i].name, name+"$")) || o.sections[i].size == 0 {
				continue
			}
			if first < 0 {
				first = i
				o.sections[i].name = name
				continue
			}
			s := o.sections[i]
			base := (uint32(len(o.sections[first].data)) + 3) &^ 3
			if uint64(base)+uint64(s.size) > 1<<32-1 {
				return fmt.Errorf("COFF SEH section too large")
			}
			o.sections[first].data = append(o.sections[first].data, make([]byte, int(base)-len(o.sections[first].data))...)
			o.sections[first].data = append(o.sections[first].data, s.data...)
			o.sections[first].size = uint32(len(o.sections[first].data))
			for _, r := range s.relocs {
				r.VirtualAddress += base
				o.sections[first].relocs = append(o.sections[first].relocs, r)
			}
			for j := 0; j < len(o.symbols); {
				sym := &o.symbols[j]
				if sym.SectionNumber == int16(i+1) {
					sym.SectionNumber = int16(first + 1)
					sym.Value += base
				}
				j += 1 + int(sym.NumberOfAuxSymbols)
			}
			o.sections[i] = section{name: ".bao.drop", flags: pe.IMAGE_SCN_MEM_DISCARDABLE}
		}
	}
	return nil
}

func (o *object) uniqueSections() {
	seen := map[string]bool{}
	for i := range o.sections {
		s := &o.sections[i]
		if s.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
			continue
		}
		s.flags &^= pe.IMAGE_SCN_LNK_COMDAT
		if seen[s.name] {
			s.name = fmt.Sprintf(".bao.s%d", i)
		}
		seen[s.name] = true
	}
}

func (o *object) addSymbol(name string, section int16, value uint32) {
	o.symbols = append(o.symbols, pe.COFFSymbol{Value: value, SectionNumber: section, StorageClass: 2})
	o.names = append(o.names, name)
}

func (o *object) encode() ([]byte, error) {
	if len(o.sections) > 0xffff {
		return nil, fmt.Errorf("too many COFF sections")
	}
	str := []byte{0, 0, 0, 0}
	name := func(n string) (r [8]byte) {
		if len(n) <= 8 {
			copy(r[:], n)
		} else {
			binary.LittleEndian.PutUint32(r[4:], uint32(len(str)))
			str = append(str, []byte(n)...)
			str = append(str, 0)
		}
		return
	}
	sectionNames := make([][8]byte, len(o.sections))
	for i, s := range o.sections {
		if len(s.name) <= 8 {
			copy(sectionNames[i][:], s.name)
		} else {
			ref := "/" + strconv.Itoa(len(str))
			if len(ref) > 8 {
				return nil, fmt.Errorf("COFF string table too large")
			}
			copy(sectionNames[i][:], ref)
			str = append(str, []byte(s.name)...)
			str = append(str, 0)
		}
	}
	var symbols bytes.Buffer
	for i := 0; i < len(o.symbols); {
		s := o.symbols[i]
		s.Name = name(o.names[i])
		binary.Write(&symbols, binary.LittleEndian, s)
		for j := 1; j <= int(s.NumberOfAuxSymbols); j++ {
			binary.Write(&symbols, binary.LittleEndian, o.symbols[i+j])
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	b := make([]byte, 20+40*len(o.sections))
	for i, s := range o.sections {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		h := b[20+40*i : 20+40*(i+1)]
		copy(h, sectionNames[i][:])
		binary.LittleEndian.PutUint32(h[16:], s.size)
		binary.LittleEndian.PutUint32(h[36:], s.flags)
		if len(s.data) > 0 {
			binary.LittleEndian.PutUint32(h[20:], uint32(len(b)))
			b = append(b, s.data...)
		}
		if len(s.relocs) > 0 { // Reacquire after append may have moved the buffer.
			h = b[20+40*i : 20+40*(i+1)]
			binary.LittleEndian.PutUint32(h[24:], uint32(len(b)))
			binary.LittleEndian.PutUint16(h[32:], uint16(len(s.relocs)))
			var rel bytes.Buffer
			for _, r := range s.relocs {
				binary.Write(&rel, binary.LittleEndian, r)
			}
			b = append(b, rel.Bytes()...)
		}
	}
	// debug/pe (also used by Go's linker) probes a 96-byte DOS header even for
	// COFF. BSS-only synthesized objects can otherwise be shorter than that.
	if len(b) < 96 {
		b = append(b, make([]byte, 96-len(b))...)
	}
	binary.LittleEndian.PutUint16(b, o.machine)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(o.sections)))
	binary.LittleEndian.PutUint32(b[4:], o.timestamp)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(o.symbols)))
	b = append(b, symbols.Bytes()...)
	binary.LittleEndian.PutUint32(str, uint32(len(str)))
	return append(b, str...), nil
}

// DWARF applies COFF section-relative debug relocations before using debug/pe.
// Debug addresses are object-relative; no runtime image addresses are inferred.
func DWARF(input []byte) (*dwarf.Data, error) {
	o, err := parse(input)
	if err != nil {
		return nil, err
	}
	for si := range o.sections {
		s := &o.sections[si]
		if !strings.HasPrefix(s.name, ".debug_") {
			continue
		}
		for _, r := range s.relocs {
			if int(r.SymbolTableIndex) >= len(o.symbols) {
				return nil, fmt.Errorf("debug relocation symbol out of bounds")
			}
			v := o.symbols[r.SymbolTableIndex]
			width := uint32(4)
			sectionRel := r.Type == 0xb
			if o.machine == pe.IMAGE_FILE_MACHINE_ARM64 {
				sectionRel = r.Type == 8
			}
			if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 1 || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 14 {
				width = 8
			}
			isSection := o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 0xa || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 13
			if isSection {
				width = 2
			}
			if !sectionRel && width != 8 && !isSection {
				return nil, fmt.Errorf("unsupported COFF debug relocation %#x", r.Type)
			}
			if uint64(r.VirtualAddress)+uint64(width) > uint64(len(s.data)) {
				return nil, fmt.Errorf("COFF debug relocation outside section")
			}
			p := s.data[r.VirtualAddress:]
			switch width {
			case 2:
				binary.LittleEndian.PutUint16(p, binary.LittleEndian.Uint16(p)+uint16(v.SectionNumber))
			case 4:
				binary.LittleEndian.PutUint32(p, binary.LittleEndian.Uint32(p)+v.Value)
			case 8:
				binary.LittleEndian.PutUint64(p, binary.LittleEndian.Uint64(p)+uint64(v.Value))
			}
		}
		s.relocs = nil
	}
	b, err := o.encode()
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.DWARF()
}
