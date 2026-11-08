package pecoff

import (
	"debug/pe"
	"sort"
	"strings"
)

// Match native linkers' locally satisfied dllimport references. Each import
// cell is ordinary linked data pointing to the local function/data definition;
// no DLL lookup, runtime code patching or extraction is involved.
func localImportCells(objects []*object, defs map[string]int) []*object {
	names := map[string]bool{}
	for _, o := range objects {
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			name := o.names[i]
			if s.StorageClass == 2 && s.SectionNumber == 0 && strings.HasPrefix(name, "__imp_") {
				if _, exists := defs[name]; !exists {
					if _, local := defs[strings.TrimPrefix(name, "__imp_")]; local {
						names[name] = true
					}
				}
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	if len(names) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	var cells []*object
	widthReloc := uint16(1)
	if objects[0].machine == pe.IMAGE_FILE_MACHINE_ARM64 {
		widthReloc = 14
	}
	for _, name := range ordered {
		o := &object{machine: objects[0].machine}
		base := strings.TrimPrefix(name, "__imp_")
		index := len(o.symbols)
		o.addSymbol(base, 0, 0)
		o.sections = append(o.sections, section{name: ".rdata", size: 8, data: make([]byte, 8), flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | 0x400000, relocs: []pe.Reloc{{SymbolTableIndex: uint32(index), Type: widthReloc}}})
		o.addSymbol(name, int16(len(o.sections)), 0)
		cells = append(cells, o)
	}
	return cells
}
