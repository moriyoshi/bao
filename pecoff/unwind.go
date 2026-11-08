package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Go emits native amd64 .pdata in input order. GCC's hot/cold contributions
// can be in a different order from their text sections. Windows binary-searches
// this array, so sort whole records by the section/address order Go will emit.
func (o *object) sortAMD64Unwind() error {
	if o.machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil
	}
	for si := range o.sections {
		s := &o.sections[si]
		if s.name != ".pdata" || s.size == 0 {
			continue
		}
		if s.size%12 != 0 || len(s.data) != int(s.size) || len(s.relocs) != int(s.size/4) {
			return fmt.Errorf("invalid amd64 runtime function table")
		}
		type record struct {
			old     int
			section int16
			address int64
			data    []byte
			relocs  []pe.Reloc
		}
		rows := make([]record, s.size/12)
		for i := range rows {
			rows[i] = record{old: i, data: append([]byte(nil), s.data[12*i:12*i+12]...)}
		}
		for _, r := range s.relocs {
			if r.Type != 3 || r.VirtualAddress%4 != 0 || r.VirtualAddress >= s.size {
				return fmt.Errorf("invalid amd64 function-table relocation")
			}
			rows[r.VirtualAddress/12].relocs = append(rows[r.VirtualAddress/12].relocs, r)
		}
		for i := range rows {
			r := &rows[i]
			sort.Slice(r.relocs, func(a, b int) bool { return r.relocs[a].VirtualAddress < r.relocs[b].VirtualAddress })
			if len(r.relocs) != 3 {
				return fmt.Errorf("incomplete amd64 function-table record")
			}
			for col, rel := range r.relocs {
				if rel.VirtualAddress != uint32(i*12+col*4) {
					return fmt.Errorf("overlapping amd64 function-table relocations")
				}
			}
			sym := o.symbols[r.relocs[0].SymbolTableIndex]
			if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(o.sections) || o.sections[sym.SectionNumber-1].flags&pe.IMAGE_SCN_CNT_CODE == 0 {
				return fmt.Errorf("amd64 function table does not reference native text")
			}
			r.section = sym.SectionNumber
			r.address = int64(sym.Value) + int64(int32(binary.LittleEndian.Uint32(r.data)))
			if r.address < 0 || r.address >= int64(o.sections[sym.SectionNumber-1].size) {
				return fmt.Errorf("amd64 function start outside text")
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].section != rows[j].section {
				return rows[i].section < rows[j].section
			}
			return rows[i].address < rows[j].address
		})
		mapping := make([]int, len(rows))
		var data []byte
		var relocs []pe.Reloc
		for i, row := range rows {
			mapping[row.old] = i
			data = append(data, row.data...)
			for _, r := range row.relocs {
				r.VirtualAddress = uint32(i*12) + r.VirtualAddress%12
				relocs = append(relocs, r)
			}
		}
		remap := func(value uint32) uint32 {
			if value >= s.size {
				return value
			}
			return uint32(mapping[value/12])*12 + value%12
		}
		oldValues := make([]uint32, len(o.symbols))
		for i := 0; i < len(o.symbols); {
			sym := &o.symbols[i]
			oldValues[i] = sym.Value
			// A zero-valued section symbol denotes the table base, not a row.
			if sym.SectionNumber == int16(si+1) && !(sym.StorageClass == 3 && sym.Type == 0 && strings.HasPrefix(o.names[i], ".") && sym.Value == 0) {
				sym.Value = remap(sym.Value)
			}
			i += 1 + int(sym.NumberOfAuxSymbols)
		}
		s.data, s.relocs = data, relocs
		for sj := range o.sections {
			sec := &o.sections[sj]
			for _, r := range sec.relocs {
				idx := r.SymbolTableIndex
				sym := o.symbols[idx]
				if sym.SectionNumber != int16(si+1) {
					continue
				}
				if uint64(r.VirtualAddress)+4 > uint64(len(sec.data)) {
					return fmt.Errorf("function-table reference out of bounds")
				}
				width := 4
				if r.Type == 1 {
					width = 8
				}
				if r.Type != 1 && r.Type != 2 && r.Type != 3 && r.Type != 4 {
					return fmt.Errorf("unsupported function-table reference")
				}
				add := int64(int32(binary.LittleEndian.Uint32(sec.data[r.VirtualAddress:])))
				if width == 8 {
					if uint64(r.VirtualAddress)+8 > uint64(len(sec.data)) {
						return fmt.Errorf("function-table reference out of bounds")
					}
					add = int64(binary.LittleEndian.Uint64(sec.data[r.VirtualAddress:]))
				}
				if oldValues[idx] == 0 && add == 0 && sym.Value == 0 {
					continue
				}
				offset := int64(oldValues[idx]) + add
				if offset < 0 || offset > int64(s.size) {
					return fmt.Errorf("function-table reference outside table")
				}
				value := int64(remap(uint32(offset))) - int64(sym.Value)
				if width == 8 {
					binary.LittleEndian.PutUint64(sec.data[r.VirtualAddress:], uint64(value))
				} else {
					binary.LittleEndian.PutUint32(sec.data[r.VirtualAddress:], uint32(value))
				}
			}
		}
	}
	return nil
}

// Go marks .pdata relocations weak and can redirect a dead text symbol to
// runtime.unreachableMethod. Root every record target through ordinary data so
// starts, ends and unwind payloads keep their actual addresses and table order.
func (o *object) keepUnwindTargets(name string) *Table {
	if o.machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil
	}
	seen := map[uint32]bool{}
	var relocs []pe.Reloc
	for _, s := range o.sections {
		if s.name == ".pdata" {
			for _, r := range s.relocs {
				if !seen[r.SymbolTableIndex] {
					seen[r.SymbolTableIndex] = true
					relocs = append(relocs, pe.Reloc{VirtualAddress: uint32(len(relocs) * 8), SymbolTableIndex: r.SymbolTableIndex, Type: 1})
				}
			}
		}
	}
	if len(relocs) == 0 {
		return nil
	}
	size := uint32(len(relocs) * 8)
	o.sections = append(o.sections, section{name: ".bao.uwr", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | 0x400000, size: size, data: make([]byte, size), relocs: relocs})
	o.addSymbol(name, int16(len(o.sections)), 0)
	return &Table{name, len(relocs), "keep native SEH targets"}
}
