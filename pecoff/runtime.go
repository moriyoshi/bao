package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func gnuInitializerPriority(name string) (int, error) {
	for _, prefix := range []string{".ctors.", ".dtors."} {
		if strings.HasPrefix(name, prefix) {
			value, err := strconv.ParseUint(strings.TrimPrefix(name, prefix), 10, 16)
			if err != nil {
				return 0, fmt.Errorf("invalid GNU COFF initializer priority %s", name)
			}
			return 65535 - int(value), nil
		}
	}
	return 65535, nil
}

func supportedCRTSection(name string) bool {
	for _, prefix := range []string{".CRT$XI", ".CRT$XC", ".CRT$XP", ".CRT$XT", ".CRT$XL", ".CRT$XD"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
func needsRuntime(o *object) bool {
	for _, s := range o.sections {
		if strings.HasPrefix(s.name, ".tls") || s.name == ".dtors" || strings.HasPrefix(s.name, ".dtors.") || supportedCRTSection(s.name) && !strings.HasPrefix(s.name, ".CRT$XC") {
			return true
		}
	}
	for _, name := range o.names {
		switch strings.TrimPrefix(name, "__imp_") {
		case "atexit", "_onexit", "__cxa_atexit", "__tlregdtor", "__dyn_tls_init", "__dyn_tls_on_demand_init", "__cxa_thread_atexit", "__emutls_get_address", "__dso_handle":
			return true
		}
	}
	return false
}

func coordinateNativeFLS(objects []*object, defs map[string]int) {
	wrappers := map[string]string{"FlsAlloc": "bao_winrt_fls_alloc", "FlsGetValue": "bao_winrt_fls_get", "FlsSetValue": "bao_winrt_fls_set", "FlsFree": "bao_winrt_fls_free"}
	for _, o := range objects {
		for i := 0; i < len(o.symbols); {
			s := o.symbols[i]
			base := strings.TrimPrefix(o.names[i], "__imp_")
			if replacement, ok := wrappers[base]; ok && s.StorageClass == 2 && s.SectionNumber == 0 {
				_, direct := defs[base]
				_, indirect := defs["__imp_"+base]
				if !direct && !indirect {
					o.names[i] = strings.TrimSuffix(o.names[i], base) + replacement
				}
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
}
func knownDataImport(name string) bool {
	return strings.HasPrefix(name, "_ZTVN10__cxxabiv1") || strings.HasPrefix(name, "_ZTI")
}
func knownFunctionImport(name string) bool {
	_, ok := systemImports[name]
	return ok && !knownDataImport(name)
}

// COFF archive indexes can advertise a weak alias whose implementation is a
// private definition in the same member (for example libc++ operator delete).
// Make the first such provider extractable by an ordinary undefined reference.
// Real strong definitions retain precedence; null/undefined fallbacks do not
// become archive providers. The original weak record is still validated later.
func indexWeakDefinitions(objects []*object, defs map[string]int) {
	for oi, o := range objects {
		limit := len(o.symbols)
		for i := 0; i < limit; {
			s := o.symbols[i]
			if s.StorageClass == 105 && s.SectionNumber == 0 && s.NumberOfAuxSymbols == 1 {
				var raw bytes.Buffer
				binary.Write(&raw, binary.LittleEndian, o.symbols[i+1])
				target := binary.LittleEndian.Uint32(raw.Bytes())
				mode := binary.LittleEndian.Uint32(raw.Bytes()[4:])
				if _, strong := defs[o.names[i]]; !strong && mode >= 1 && mode <= 3 && int(target) < limit && o.names[target] != "" {
					t := o.symbols[target]
					if t.SectionNumber > 0 && int(t.SectionNumber) <= len(o.sections) && (t.StorageClass == 2 || t.StorageClass == 3) {
						o.addSymbol(o.names[i], t.SectionNumber, t.Value)
						o.symbols[len(o.symbols)-1].Type = t.Type
						defs[o.names[i]] = oi
					}
				}
			}
			i += 1 + int(s.NumberOfAuxSymbols)
		}
	}
}

// The authored helper supplies fallback services. An explicitly linked native
// runtime may provide the real service instead. Keep the helper's internal
// references local in that case, without exporting a second strong definition.
func localizeRuntimeFallbacks(helper *object, defs map[string]int) {
	for i := 0; i < len(helper.symbols); {
		s := &helper.symbols[i]
		if s.StorageClass == 2 && s.SectionNumber > 0 {
			if _, exists := defs[helper.names[i]]; exists {
				s.StorageClass = 3
			}
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
}

// Resolve COFF's auxiliary weak-external alias records before Go sees them.
// NOLIBRARY/ALIAS consult selected strong definitions; LIBRARY may extract one.
// Anti-dependencies have different selection semantics and remain an error.
func (o *object) resolveWeak(defs map[string]int, selected map[int]bool) error {
	zeros := map[uint32]bool{}
	var resolve func(uint32, map[uint32]bool) (uint32, error)
	resolve = func(i uint32, seen map[uint32]bool) (uint32, error) {
		if int(i) >= len(o.symbols) || o.names[i] == "" {
			return 0, fmt.Errorf("invalid COFF weak-external target")
		}
		s := o.symbols[i]
		if s.StorageClass != 105 {
			return i, nil
		}
		if seen[i] {
			return 0, fmt.Errorf("cyclic COFF weak-external aliases")
		}
		seen[i] = true
		if s.SectionNumber != 0 || s.Value != 0 || s.NumberOfAuxSymbols != 1 {
			return 0, fmt.Errorf("invalid COFF weak-external record")
		}
		var raw bytes.Buffer
		binary.Write(&raw, binary.LittleEndian, o.symbols[i+1])
		index := binary.LittleEndian.Uint32(raw.Bytes())
		mode := binary.LittleEndian.Uint32(raw.Bytes()[4:])
		if mode < 1 || mode > 3 {
			return 0, fmt.Errorf("unsupported COFF weak-external search policy %d", mode)
		}
		if int(index) >= len(o.symbols) || o.names[index] == "" {
			return 0, fmt.Errorf("invalid COFF weak-external target")
		}
		if o.symbols[index].SectionNumber == -1 && o.symbols[index].Value == 0 {
			zeros[index] = true
		}
		if owner, ok := defs[o.names[i]]; ok && (mode == 2 || selected[owner]) {
			o.symbols[i].StorageClass = 2
			return i, nil
		}
		return resolve(index, seen)
	}
	// Also validate and discard an unused absolute-zero fallback when a strong
	// definition wins, or when optimization removed the weak reference itself.
	for i := 0; i < len(o.symbols); {
		if o.symbols[i].StorageClass == 105 {
			if _, err := resolve(uint32(i), map[uint32]bool{}); err != nil {
				return err
			}
		}
		i += 1 + int(o.symbols[i].NumberOfAuxSymbols)
	}
	for si := range o.sections {
		for ri := range o.sections[si].relocs {
			r := &o.sections[si].relocs[ri]
			i, err := resolve(r.SymbolTableIndex, map[uint32]bool{})
			if err != nil {
				return err
			}
			if o.symbols[r.SymbolTableIndex].StorageClass == 105 && o.symbols[i].SectionNumber == -1 && o.symbols[i].Value == 0 {
				zeros[i] = true
			}
			r.SymbolTableIndex = i
		}
	}
	if err := o.resolveWeakZeros(zeros); err != nil {
		return err
	}
	// Orphan alias records are now ordinary undefined symbols. Clear auxiliary
	// records only by rebuilding the symbol table, retaining all index mappings.
	for i := 0; i < len(o.symbols); {
		n := 1 + int(o.symbols[i].NumberOfAuxSymbols)
		if o.symbols[i].StorageClass == 105 {
			o.symbols[i].StorageClass = 2
		}
		i += n
	}
	return nil
}

func (o *object) fixDataImports(p *Plan, needed map[string]bool, imports map[string]string, oi int) error {
	for si := range o.sections {
		s := &o.sections[si]
		var relocs []pe.Reloc
		for _, r := range s.relocs {
			name := o.names[r.SymbolTableIndex]
			if !needed[name] || !knownDataImport(name) {
				relocs = append(relocs, r)
				continue
			}
			if !(p.Arch == "amd64" && r.Type == 1 || p.Arch == "arm64" && r.Type == 14) || uint64(r.VirtualAddress)+8 > uint64(len(s.data)) || s.flags&pe.IMAGE_SCN_CNT_CODE != 0 {
				return fmt.Errorf("DLL data import %s requires an absolute pointer in data", name)
			}
			symbol := fmt.Sprintf("%sdata_import_%d_%d_%d", p.Namespace, oi, si, r.VirtualAddress)
			s.flags |= pe.IMAGE_SCN_MEM_WRITE
			o.addSymbol(symbol, int16(si+1), 0)
			p.DataImports = append(p.DataImports, DataImport{symbol, name, imports[name], r.VirtualAddress, binary.LittleEndian.Uint64(s.data[r.VirtualAddress:])})
			clear(s.data[r.VirtualAddress : r.VirtualAddress+8])
		}
		s.relocs = relocs
	}
	return nil
}

func prepareTLS(objects []*object, selected map[int]bool, p *Plan) error {
	type key struct {
		object  int
		section int16
	}
	offsets := map[key]uint32{}
	globals := map[string]uint32{}
	var template []byte
	align := uint32(8)
	// COFF TLS contributions are ordered by their $ suffix, then input order.
	type contribution struct {
		oi, si int
		order  string
	}
	var parts []contribution
	for oi, o := range objects {
		if selected[oi] {
			for si, s := range o.sections {
				if strings.HasPrefix(s.name, ".tls") {
					parts = append(parts, contribution{oi, si, s.name})
				}
			}
		}
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].order < parts[j].order })
	for _, part := range parts {
		s := &objects[part.oi].sections[part.si]
		if len(s.relocs) != 0 {
			return fmt.Errorf("relocations in Windows TLS templates are unsupported")
		}
		a := uint32(1)
		if bits := (s.flags >> 20) & 15; bits != 0 {
			a = 1 << (bits - 1)
		}
		if a > 8192 {
			return fmt.Errorf("Windows TLS alignment exceeds 8192")
		}
		if a > align {
			align = a
		}
		base := (uint64(len(template)) + uint64(a) - 1) &^ uint64(a-1)
		if base+uint64(s.size) > 64<<20 {
			return fmt.Errorf("Windows TLS template exceeds 64 MiB")
		}
		template = append(template, make([]byte, int(base)+int(s.size)-len(template))...)
		copy(template[base:], s.data)
		offsets[key{part.oi, int16(part.si + 1)}] = uint32(base)
		s.name = ".bao.tls"
		s.flags = s.flags&^0xf00000 | 0x400000 // template address is not thread storage
	}
	for oi, o := range objects {
		if selected[oi] {
			for i := 0; i < len(o.symbols); {
				s := o.symbols[i]
				if base, ok := offsets[key{oi, s.SectionNumber}]; ok && s.StorageClass == 2 {
					globals[o.names[i]] = base + s.Value
				}
				i += 1 + int(s.NumberOfAuxSymbols)
			}
		}
	}
	for oi, o := range objects {
		if !selected[oi] {
			continue
		}
		for si := range o.sections {
			s := &o.sections[si]
			if debugSection(s.name) || s.flags&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
				continue
			}
			var relocs []pe.Reloc
			tlsRelocs := 0
			for _, r := range s.relocs {
				sym := o.symbols[r.SymbolTableIndex]
				base, ok := offsets[key{oi, sym.SectionNumber}]
				if ok && sym.Value >= o.sections[sym.SectionNumber-1].size {
					return fmt.Errorf("Windows TLS symbol outside template contribution")
				}
				value := uint64(base) + uint64(sym.Value)
				if !ok && sym.SectionNumber == 0 {
					if global, found := globals[o.names[r.SymbolTableIndex]]; found {
						ok = true
						value = uint64(global)
					}
				}
				if !ok {
					relocs = append(relocs, r)
					continue
				}
				// Rust std exports local __imp_ aliases for its data, including
				// TLS definitions. Native linkers point these cells at the image's
				// TLS template, not at any thread's storage. Retain that ordinary
				// address relocation; only actual TLS instructions use private FLS.
				if o.tlsImportAlias(si, r, p.Arch) {
					relocs = append(relocs, r)
					continue
				}
				if uint64(r.VirtualAddress)+4 > uint64(len(s.data)) {
					return fmt.Errorf("Windows TLS relocation out of bounds")
				}
				instruction := binary.LittleEndian.Uint32(s.data[r.VirtualAddress:])
				if p.Arch == "amd64" && r.Type == 0xb {
					if value+uint64(instruction) > 1<<32-1 {
						return fmt.Errorf("Windows TLS offset overflow")
					}
					instruction += uint32(value)
				} else if p.Arch == "arm64" && (r.Type == 9 || r.Type == 10 || r.Type == 11) {
					switch r.Type {
					case 9, 10:
						if instruction&0xff000000 != 0x91000000 || (instruction>>22)&1 != uint32(r.Type-9) {
							return fmt.Errorf("unrecognized Windows TLS ADD instruction")
						}
						shift := uint(0)
						if r.Type == 10 {
							shift = 12
						}
						add := (value >> shift) & 0xfff
						if (value>>24) != 0 || uint64((instruction>>10)&0xfff)+add > 0xfff {
							return fmt.Errorf("Windows TLS ADD offset overflow")
						}
						instruction += uint32(add) << 10
					case 11:
						if instruction&0x3b000000 != 0x39000000 {
							return fmt.Errorf("unrecognized Windows TLS load/store instruction")
						}
						scale := uint(instruction >> 30)
						if instruction&(1<<26) != 0 && instruction&(1<<23) != 0 {
							scale = 4
						}
						low := value & 0xfff
						if low&((1<<scale)-1) != 0 {
							return fmt.Errorf("unaligned Windows TLS load/store")
						}
						add := low >> scale
						if uint64((instruction>>10)&0xfff)+add > 0xfff {
							return fmt.Errorf("Windows TLS load/store offset overflow")
						}
						instruction += uint32(add) << 10
					}
				} else {
					return fmt.Errorf("unsupported relocation %#x to native Windows TLS", r.Type)
				}
				binary.LittleEndian.PutUint32(s.data[r.VirtualAddress:], instruction)
				tlsRelocs++
			}
			s.relocs = relocs
			if tlsRelocs > 0 {
				n, err := o.patchTLSReads(si, p.Arch)
				if err != nil {
					return err
				}
				if n == 0 {
					return fmt.Errorf("native Windows TLS access has no recognized TEB array load")
				}
				p.TLS.Accesses += n
			}
		}
	}
	if len(parts) > 0 {
		o := objects[len(objects)-1]
		p.TLS.Symbol = p.Namespace + "tls_template"
		p.TLS.Size = uint32(len(template))
		p.TLS.Alignment = align
		o.sections = append(o.sections, section{name: ".bao.tpl", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | 0x400000, size: uint32(len(template)), data: template})
		o.addSymbol(p.TLS.Symbol, int16(len(o.sections)), 0)
	}
	return nil
}

func (o *object) tlsImportAlias(si int, r pe.Reloc, arch string) bool {
	s := o.sections[si]
	if !(arch == "amd64" && r.Type == 1 || arch == "arm64" && r.Type == 14) || r.VirtualAddress != 0 || s.size != 8 || len(s.data) != 8 || len(s.relocs) != 1 || s.flags&pe.IMAGE_SCN_CNT_CODE != 0 || binary.LittleEndian.Uint64(s.data) != 0 {
		return false
	}
	want := "__imp_" + o.names[r.SymbolTableIndex]
	found := false
	for i := 0; i < len(o.symbols); {
		sym := o.symbols[i]
		if sym.SectionNumber == int16(si+1) && sym.StorageClass == 2 {
			if found || o.names[i] != want || sym.Value != 0 {
				return false
			}
			found = true
		}
		i += 1 + int(sym.NumberOfAuxSymbols)
	}
	return found
}
