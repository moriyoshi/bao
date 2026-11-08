package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

type sectionRef struct{ object, section int }
type comdat struct {
	ref       sectionRef
	key       string
	selection byte
	parent    int
}

func cloneObjects(src []*object) []*object {
	dst := make([]*object, len(src))
	for i, o := range src {
		c := *o
		c.symbols = append([]pe.COFFSymbol(nil), o.symbols...)
		c.names = append([]string(nil), o.names...)
		c.sections = append([]section(nil), o.sections...)
		for j := range c.sections {
			c.sections[j].data = append([]byte(nil), o.sections[j].data...)
			c.sections[j].relocs = append([]pe.Reloc(nil), o.sections[j].relocs...)
		}
		dst[i] = &c
	}
	return dst
}

// selectCOMDAT operates on the extracted archive members before dependency
// discovery, TLS layout or SEH merging. References into discarded sections are
// made ordinary external references to anchors in the selected contributions.
func selectCOMDAT(objects []*object, selected map[int]bool, defs map[string]int, namespace string) error {
	all := map[sectionRef]*comdat{}
	groups := map[string][]*comdat{}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		for si, sec := range o.sections {
			if sec.flags&pe.IMAGE_SCN_LNK_COMDAT == 0 {
				continue
			}
			c := &comdat{ref: sectionRef{oi, si}, parent: -1}
			found := false
			localKey := ""
			for i := 0; i < len(o.symbols); {
				s := o.symbols[i]
				if s.SectionNumber == int16(si+1) && s.StorageClass == 3 && s.Value == 0 && s.NumberOfAuxSymbols > 0 && o.names[i] == sec.name {
					if found || s.NumberOfAuxSymbols != 1 {
						return fmt.Errorf("invalid COMDAT section definition in %s", sec.name)
					}
					var b bytes.Buffer
					binary.Write(&b, binary.LittleEndian, o.symbols[i+1])
					raw := b.Bytes()
					c.selection = raw[14]
					c.parent = int(binary.LittleEndian.Uint16(raw[12:])) - 1
					if binary.LittleEndian.Uint16(raw[16:]) != 0 {
						return fmt.Errorf("unsupported COMDAT high section number")
					}
					found = true
				}
				if s.SectionNumber == int16(si+1) && s.StorageClass == 2 && c.key == "" {
					c.key = "external:" + o.names[i]
				}
				if s.SectionNumber == int16(si+1) && s.StorageClass == 3 && s.NumberOfAuxSymbols == 0 && localKey == "" {
					localKey = o.names[i]
				}
				i += 1 + int(s.NumberOfAuxSymbols)
			}
			if !found || c.selection < 1 || c.selection > 7 {
				return fmt.Errorf("missing or unsupported COMDAT selection in %s", sec.name)
			}
			if c.selection != 5 && c.key == "" {
				// GNU COFF emits independently keyed .pdata$<function> and
				// .xdata$<function> contributions with only a static section
				// symbol. Their full section name is the COMDAT identity.
				if localKey != "" {
					c.key = fmt.Sprintf("local:%d:%s", oi, localKey)
				} else if strings.HasPrefix(sec.name, ".xdata$") || strings.HasPrefix(sec.name, ".pdata$") {
					c.key = "section:" + sec.name
				} else if debugSection(sec.name) {
					// GCC emits private debug-frame COMDATs without leaders.
					// They do not participate in runtime symbol selection.
					c.key = fmt.Sprintf("debug:%d:%d", oi, si)
				} else {
					return fmt.Errorf("COMDAT section %s has no identifiable leader", sec.name)
				}
			}
			all[c.ref] = c
			if c.selection != 5 {
				groups[c.key] = append(groups[c.key], c)
			}
		}
	}
	// Validate even association chains that will subsequently be discarded.
	var root func(sectionRef, map[sectionRef]bool) (sectionRef, error)
	root = func(r sectionRef, visiting map[sectionRef]bool) (sectionRef, error) {
		c := all[r]
		if c == nil {
			return r, fmt.Errorf("COMDAT association references a non-COMDAT section")
		}
		if visiting[r] {
			return r, fmt.Errorf("COMDAT association cycle")
		}
		if c.selection != 5 {
			return r, nil
		}
		visiting[r] = true
		return root(sectionRef{r.object, c.parent}, visiting)
	}
	for r := range all {
		if _, err := root(r, map[sectionRef]bool{}); err != nil {
			return err
		}
	}
	losers := map[sectionRef]sectionRef{}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cs := groups[key]
		win := cs[0]
		for _, c := range cs[1:] {
			if c.selection != win.selection {
				return fmt.Errorf("conflicting COMDAT selection for %s", key)
			}
			a, b := objects[win.ref.object].sections[win.ref.section], objects[c.ref.object].sections[c.ref.section]
			switch c.selection {
			case 1:
				return fmt.Errorf("duplicate NODUPLICATES COMDAT %s", key)
			case 3:
				if a.size != b.size {
					return fmt.Errorf("SAME_SIZE COMDAT mismatch for %s", key)
				}
			case 4:
				if !equalCOMDAT(objects, win.ref, c.ref) {
					return fmt.Errorf("EXACT_MATCH COMDAT mismatch for %s", key)
				}
			case 6:
				if b.size > a.size {
					win = c
				}
			case 7:
				if objects[c.ref.object].timestamp > objects[win.ref.object].timestamp {
					win = c
				}
			}
		}
		for _, c := range cs {
			if c != win {
				losers[c.ref] = win.ref
			}
		}
	}
	// An associated section follows its parent's decision, including nested
	// associations. Match siblings by section name and occurrence for references
	// from surviving code into a discarded metadata contribution.
	var associate func(sectionRef) (sectionRef, bool, error)
	associate = func(r sectionRef) (sectionRef, bool, error) {
		if w, ok := losers[r]; ok {
			return w, true, nil
		}
		c := all[r]
		if c.selection != 5 {
			return r, false, nil
		}
		p := sectionRef{r.object, c.parent}
		w, discarded, err := associate(p)
		if err != nil || !discarded {
			return r, false, err
		}
		if w.object < 0 {
			losers[r] = w
			return w, true, nil
		}
		ordinal := 0
		name := objects[r.object].sections[r.section].name
		for si := 0; si < r.section; si++ {
			x := all[sectionRef{r.object, si}]
			if x != nil && x.selection == 5 && x.parent == p.section && objects[r.object].sections[si].name == name {
				ordinal++
			}
		}
		for si, sec := range objects[w.object].sections {
			x := all[sectionRef{w.object, si}]
			if x != nil && x.selection == 5 && x.parent == w.section && sec.name == name {
				if ordinal == 0 {
					losers[r] = x.ref
					return x.ref, true, nil
				}
				ordinal--
			}
		}
		// No counterpart is needed unless retained code actually references it.
		losers[r] = sectionRef{-1, -1}
		return sectionRef{-1, -1}, true, nil
	}
	refs := make([]sectionRef, 0, len(all))
	for r := range all {
		refs = append(refs, r)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].object != refs[j].object {
			return refs[i].object < refs[j].object
		}
		return refs[i].section < refs[j].section
	})
	for _, r := range refs {
		if _, _, err := associate(r); err != nil {
			return err
		}
	}
	// Make selected surviving definitions take precedence over the archive index.
	surviving := map[string]bool{}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			if s.StorageClass == 2 && s.SectionNumber > 0 {
				if _, drop := losers[sectionRef{oi, int(s.SectionNumber) - 1}]; !drop {
					defs[o.names[i]] = oi
					surviving[o.names[i]] = true
				}
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		// Only retained relocations require aliases for local/section symbols.
		referenced := map[uint32]bool{}
		for si, sec := range o.sections {
			if _, drop := losers[sectionRef{oi, si}]; drop || debugSection(sec.name) || sec.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
				continue
			}
			for _, r := range sec.relocs {
				referenced[r.SymbolTableIndex] = true
			}
		}
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			if s.StorageClass == 105 && s.NumberOfAuxSymbols == 1 {
				var b bytes.Buffer
				binary.Write(&b, binary.LittleEndian, o.symbols[i+1])
				referenced[binary.LittleEndian.Uint32(b.Bytes())] = true
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
		for i := 0; i < len(o.symbols); {
			s := &o.symbols[i]
			next := i + 1 + int(s.NumberOfAuxSymbols)
			w, drop := losers[sectionRef{oi, int(s.SectionNumber) - 1}]
			if s.SectionNumber > 0 && drop {
				name := o.names[i]
				if s.StorageClass == 2 && surviving[name] {
					// A matching external definition is the canonical address.
				} else if referenced[uint32(i)] || s.StorageClass == 2 {
					if w.object < 0 || s.Value > objects[w.object].sections[w.section].size {
						return fmt.Errorf("retained reference has no winning COMDAT counterpart for %s", name)
					}
					if s.StorageClass != 2 {
						name = fmt.Sprintf("%scomdat_%d_%d_%d", namespace, w.object, w.section, s.Value)
					}
					if !surviving[name] {
						typ := s.Type
						objects[w.object].addSymbol(name, int16(w.section+1), s.Value)
						objects[w.object].symbols[len(objects[w.object].symbols)-1].Type = typ
					}
					defs[name] = w.object
					surviving[name] = true
				} else {
					name = fmt.Sprintf("%sdiscard_%d_%d", namespace, oi, i)
				}
				o.names[i] = name
				// addSymbol may reallocate this object's symbols slice.
				o.symbols[i].SectionNumber, o.symbols[i].StorageClass, o.symbols[i].Value = 0, 2, 0
			}
			i = next
		}
	}
	for r := range losers {
		objects[r.object].sections[r.section] = section{name: ".bao.drop", flags: pe.IMAGE_SCN_MEM_DISCARDABLE}
	}
	// Section-definition auxiliary bytes are no longer valid on a redirected
	// undefined external. Remove them and preserve weak-alias index references.
	if len(losers) > 0 {
		for oi, o := range objects {
			if !selected[oi] {
				continue
			}
			remap := map[uint32]uint32{}
			var symbols []pe.COFFSymbol
			var names []string
			for i := 0; i < len(o.symbols); {
				s := o.symbols[i]
				n := 1 + int(s.NumberOfAuxSymbols)
				remap[uint32(i)] = uint32(len(symbols))
				keep := n
				if s.SectionNumber == 0 && s.StorageClass == 2 {
					s.NumberOfAuxSymbols = 0
					keep = 1
				}
				symbols = append(symbols, s)
				names = append(names, o.names[i])
				symbols = append(symbols, o.symbols[i+1:i+keep]...)
				names = append(names, o.names[i+1:i+keep]...)
				i += n
			}
			for si := range o.sections {
				for ri := range o.sections[si].relocs {
					r := &o.sections[si].relocs[ri]
					idx, ok := remap[r.SymbolTableIndex]
					if !ok {
						return fmt.Errorf("COMDAT relocation references a non-primary symbol")
					}
					r.SymbolTableIndex = idx
				}
			}
			for i := 0; i < len(symbols); {
				s := symbols[i]
				if s.StorageClass == 105 && s.NumberOfAuxSymbols == 1 {
					var b bytes.Buffer
					binary.Write(&b, binary.LittleEndian, symbols[i+1])
					raw := b.Bytes()
					idx, ok := remap[binary.LittleEndian.Uint32(raw)]
					if !ok {
						return fmt.Errorf("COMDAT weak alias references a non-primary symbol")
					}
					binary.LittleEndian.PutUint32(raw, idx)
					binary.Read(bytes.NewReader(raw), binary.LittleEndian, &symbols[i+1])
				}
				i += 1 + int(s.NumberOfAuxSymbols)
			}
			o.symbols, o.names = symbols, names
		}
	}
	return nil
}

// Compare relocation meaning, never raw symbol-table indices or just the
// producer checksum. Section-local targets are relative to their contribution.
func equalCOMDAT(objects []*object, a, b sectionRef) bool {
	x, y := objects[a.object].sections[a.section], objects[b.object].sections[b.section]
	if x.size != y.size || !bytes.Equal(x.data, y.data) || len(x.relocs) != len(y.relocs) {
		return false
	}
	semantic := func(r pe.Reloc, ref sectionRef) string {
		o := objects[ref.object]
		if int(r.SymbolTableIndex) >= len(o.symbols) {
			return "invalid"
		}
		s := o.symbols[r.SymbolTableIndex]
		if s.SectionNumber == int16(ref.section+1) && (s.StorageClass == 0 || s.StorageClass == 3 || s.StorageClass == 6) {
			return fmt.Sprintf("self:%d", s.Value)
		}
		if s.StorageClass == 2 || s.SectionNumber == 0 {
			return "external:" + o.names[r.SymbolTableIndex]
		}
		// Cross-contribution local identities are not provably interchangeable.
		return fmt.Sprintf("local:%d:%d:%d", ref.object, s.SectionNumber, s.Value)
	}
	xr, yr := append([]pe.Reloc(nil), x.relocs...), append([]pe.Reloc(nil), y.relocs...)
	sort.Slice(xr, func(i, j int) bool { return xr[i].VirtualAddress < xr[j].VirtualAddress })
	sort.Slice(yr, func(i, j int) bool { return yr[i].VirtualAddress < yr[j].VirtualAddress })
	for i, r := range xr {
		q := yr[i]
		if r.VirtualAddress != q.VirtualAddress || r.Type != q.Type || semantic(r, a) != semantic(q, b) || semantic(r, a) == "invalid" {
			return false
		}
	}
	return true
}
