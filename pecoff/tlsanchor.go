package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// MinGW winpthreads' _include_tls_used is an unused const pointer that asks a
// PE linker to retain its TLS directory/callbacks. Bao instead collects .CRT$XL
// callbacks and dispatches them through its private native TLS lifecycle. Lower
// only that checked metadata anchor; actual TLS-directory reads remain errors.
func (o *object) lowerTLSDirectoryAnchor() error {
	for i := 0; i < len(o.symbols); {
		s := o.symbols[i]
		next := i + 1 + int(s.NumberOfAuxSymbols)
		if o.names[i] != "_include_tls_used" || s.StorageClass != 3 || s.SectionNumber <= 0 || int(s.SectionNumber) > len(o.sections) {
			i = next
			continue
		}
		sec := &o.sections[s.SectionNumber-1]
		if sec.flags&(pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_MEM_WRITE) != 0 || sec.flags&pe.IMAGE_SCN_MEM_READ == 0 || uint64(s.Value)+8 > uint64(len(sec.data)) {
			return fmt.Errorf("unsupported _include_tls_used anchor layout")
		}
		at := -1
		for ri, r := range sec.relocs {
			if r.VirtualAddress != s.Value {
				continue
			}
			if at >= 0 || int(r.SymbolTableIndex) >= len(o.names) || o.names[r.SymbolTableIndex] != "_tls_used" || !(o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type == 1 || o.machine == pe.IMAGE_FILE_MACHINE_ARM64 && r.Type == 14) || binary.LittleEndian.Uint64(sec.data[s.Value:]) != 0 {
				return fmt.Errorf("unsupported _include_tls_used anchor relocation")
			}
			at = ri
		}
		if at < 0 {
			return fmt.Errorf("missing _include_tls_used anchor relocation")
		}
		for si, from := range o.sections {
			if debugSection(from.name) || from.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
				continue
			}
			for ri, r := range from.relocs {
				if si == int(s.SectionNumber)-1 && ri == at {
					continue
				}
				if int(r.SymbolTableIndex) >= len(o.symbols) {
					return fmt.Errorf("invalid COFF anchor reference")
				}
				target := o.symbols[r.SymbolTableIndex]
				if target.SectionNumber != s.SectionNumber {
					continue
				}
				if int(r.SymbolTableIndex) == i {
					return fmt.Errorf("TLS directory anchor has a retained reference")
				}
				var add int64
				if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 && r.Type >= 1 && r.Type <= 9 {
					width := uint64(4)
					if r.Type == 1 {
						width = 8
					}
					if uint64(r.VirtualAddress)+width > uint64(len(from.data)) {
						return fmt.Errorf("invalid COFF anchor reference bounds")
					}
					add = int64(int32(binary.LittleEndian.Uint32(from.data[r.VirtualAddress:])))
					if width == 8 {
						add = int64(binary.LittleEndian.Uint64(from.data[r.VirtualAddress:]))
					}
				} else {
					return fmt.Errorf("unrecognized reference into TLS anchor section")
				}
				address := int64(target.Value) + add
				if address >= int64(s.Value) && address < int64(s.Value)+8 {
					return fmt.Errorf("TLS directory anchor has a retained section-relative reference")
				}
			}
		}
		sec.relocs = append(sec.relocs[:at], sec.relocs[at+1:]...)
		i = next
	}
	return nil
}
