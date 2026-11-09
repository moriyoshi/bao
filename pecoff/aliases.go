package pecoff

import (
	"debug/pe"
	"strings"
)

// foldTextAliases keeps one definition per native text address. Go's findfunc
// table allows about 256 functions per 4 KiB, and LLVM's mergefunc leaves large
// groups of symbols on one body. Only Rust/Itanium-mangled externals and local
// labels fold; requested exports and other external names stay. Relocations in
// the defining object move to the representative, and references from other
// objects are renamed to it, so no native bytes or addresses change.
func foldTextAliases(objects []*object, selected map[int]bool, exports map[string]bool) int {
	retained := func(o *object, i int) bool {
		name := o.names[i]
		return exports[name] || o.symbols[i].StorageClass == 2 && !strings.HasPrefix(name, "_R") && !strings.HasPrefix(name, "_ZN")
	}
	renamed := map[string]string{}
	folded := 0
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		type location struct {
			section int16
			value   uint32
		}
		groups := map[location][]int{}
		var order []location
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			aux := int(s.NumberOfAuxSymbols)
			if aux == 0 && s.SectionNumber > 0 && int(s.SectionNumber) <= len(o.sections) && (s.StorageClass == 2 || s.StorageClass == 3) &&
				o.sections[s.SectionNumber-1].flags&pe.IMAGE_SCN_CNT_CODE != 0 && !strings.HasPrefix(o.names[i], ".") {
				at := location{s.SectionNumber, s.Value}
				if _, ok := groups[at]; !ok {
					order = append(order, at)
				}
				groups[at] = append(groups[at], i)
			}
			i += 1 + aux
		}
		representative := map[uint32]uint32{}
		for _, at := range order {
			indices := groups[at]
			canonical := indices[0]
			for _, i := range indices {
				if retained(o, i) {
					canonical = i
					break
				}
				if o.symbols[i].StorageClass == 2 && o.symbols[canonical].StorageClass != 2 {
					canonical = i
				}
			}
			for _, i := range indices {
				if i == canonical || retained(o, i) {
					continue
				}
				representative[uint32(i)] = uint32(canonical)
				if o.symbols[i].StorageClass == 2 {
					renamed[o.names[i]] = o.names[canonical]
				}
				// An unreferenced undefined record keeps symbol indices stable.
				o.symbols[i].SectionNumber = 0
				o.symbols[i].Value = 0
				o.symbols[i].StorageClass = 2
				folded++
			}
		}
		for si := range o.sections {
			for ri := range o.sections[si].relocs {
				r := &o.sections[si].relocs[ri]
				if canonical, ok := representative[r.SymbolTableIndex]; ok {
					r.SymbolTableIndex = canonical
				}
			}
		}
	}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			if s.StorageClass == 2 && s.SectionNumber == 0 {
				if canonical, ok := renamed[o.names[i]]; ok {
					o.names[i] = canonical
				}
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	return folded
}
