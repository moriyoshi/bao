package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
)

// LLVM uses SHT_X86_64_UNWIND for the same bounded .eh_frame payload that GCC
// emits as PROGBITS. Other processor-specific sections remain unsupported.
func normalizeAMD64Unwind(s *section) error {
	if s.typ != elf.SectionType(0x70000001) || s.name != ".eh_frame" || s.flags&elf.SHF_ALLOC == 0 || s.flags&(elf.SHF_EXECINSTR|elf.SHF_TLS|elf.SHF_COMPRESSED) != 0 {
		return fmt.Errorf("unsupported AMD64 unwind section layout")
	}
	if err := validateFrames(s.data); err != nil {
		return err
	}
	s.typ = elf.SHT_PROGBITS
	return nil
}

// GD/LD use the ordinary SysV __tls_get_addr ABI: descriptor in RDI, pointer
// result in RAX. Unlike GNU2 TLSDESC, this call may clobber C caller-save regs.
// We retain the compiler's instructions, including GD relaxation padding, but
// make their RIP-relative LEA address our private descriptor directly.
func validateAMD64TLSCall(s *section, address, call reloc, symbols []symbol, resolver string) error {
	if address.add != -4 || address.off < 3 || address.off+4 > uint64(len(s.data)) || !bytes.Equal(s.data[address.off-3:address.off], []byte{0x48, 0x8d, 0x3d}) {
		return fmt.Errorf("unsupported AMD64 GD/LD TLS descriptor LEA")
	}
	if elf.R_X86_64(call.typ) != elf.R_X86_64_PLT32 || call.add != -4 || symbols[call.sym].name != resolver || call.off < address.off+5 || call.off > address.off+8 || call.off+4 > uint64(len(s.data)) {
		return fmt.Errorf("unsupported AMD64 GD/LD TLS resolver call")
	}
	between := s.data[address.off+4 : call.off]
	if !bytes.Equal(between, []byte{0xe8}) && !bytes.Equal(between, []byte{0x66, 0x66, 0x48, 0xe8}) {
		return fmt.Errorf("unsupported AMD64 TLS call padding/instruction")
	}
	return nil
}

// GNU2 TLSDESC addresses a descriptor with LEA disp32(%rip) into any 64-bit
// register. The compiler then calls through the descriptor's first word with
// the descriptor in RAX; the result is an offset from the thread pointer.
func validateAMD64TLSDescriptorLEA(s *section, r reloc) error {
	if r.add != -4 || r.off < 3 || r.off+4 > uint64(len(s.data)) {
		return fmt.Errorf("unsupported AMD64 TLSDESC descriptor LEA")
	}
	b := s.data[r.off-3 : r.off]
	if b[0]&0xfb != 0x48 || b[1] != 0x8d || b[2]&0xc7 != 0x05 {
		return fmt.Errorf("unsupported AMD64 TLSDESC descriptor LEA")
	}
	return nil
}

func validateAMD64TLSDescriptorCall(s *section, r reloc, symbols []symbol) error {
	sym := symbols[r.sym]
	if r.add != 0 || r.off+2 > uint64(len(s.data)) || !bytes.Equal(s.data[r.off:r.off+2], []byte{0xff, 0x10}) {
		return fmt.Errorf("unsupported AMD64 TLSDESC call; requires CALL *(%%rax)")
	}
	if !amd64TLSModuleBase(sym) && (sym.sect == 0 || elf.ST_TYPE(sym.info) != elf.STT_TLS) {
		return fmt.Errorf("AMD64 TLSDESC call target is not local image TLS")
	}
	return nil
}

// Local-dynamic TLSDESC computes this image's TLS block base, then adds
// DTPOFF offsets. The linker would define this symbol at the module's TLS start.
func amd64TLSModuleBase(s symbol) bool {
	return s.name == "_TLS_MODULE_BASE_" && s.sect == 0
}

func foldAMD64TLSOffset(s *section, r reloc, symbols []symbol, offsets map[uint16]uint64, size uint64) error {
	sym := symbols[r.sym]
	base, ok := offsets[sym.sect]
	value := int64(base+sym.value) + r.add
	width := uint64(4)
	if elf.R_X86_64(r.typ) == elf.R_X86_64_DTPOFF64 {
		width = 8
	}
	if !ok || elf.ST_TYPE(sym.info) != elf.STT_TLS || value < 0 || uint64(value) >= size || r.off+width > uint64(len(s.data)) || width == 4 && value > 1<<31-1 {
		return fmt.Errorf("invalid AMD64 local-dynamic TLS offset")
	}
	if width == 4 {
		binary.LittleEndian.PutUint32(s.data[r.off:], uint32(value))
	} else {
		binary.LittleEndian.PutUint64(s.data[r.off:], uint64(value))
	}
	return nil
}

func amd64Supported(t elf.R_X86_64) bool {
	switch t {
	case elf.R_X86_64_NONE, elf.R_X86_64_64, elf.R_X86_64_PC32, elf.R_X86_64_PC64, elf.R_X86_64_PLT32, elf.R_X86_64_GOTPCREL, elf.R_X86_64_GOTPCRELX, elf.R_X86_64_REX_GOTPCRELX:
		return true
	}
	return false
}

func amd64GOT(t elf.R_X86_64) bool {
	return t == elf.R_X86_64_GOTPCREL || t == elf.R_X86_64_GOTPCRELX || t == elf.R_X86_64_REX_GOTPCRELX
}

func (p *Plan) bindAMD64(images []*image, index map[string]string) error {
	defined, weak, strong := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if elf.ST_BIND(s.info) == elf.STB_LOCAL || s.name == "_GLOBAL_OFFSET_TABLE_" {
				continue
			}
			if s.sect != 0 {
				defined[s.name] = true
			} else if elf.ST_BIND(s.info) == elf.STB_WEAK {
				weak[s.name] = true
			} else {
				strong[s.name] = true
			}
		}
	}
	var names []string
	for name := range strong {
		if !defined[name] {
			names = append(names, name)
		}
	}
	for name := range weak {
		if !defined[name] && !strong[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	imports, missing := map[string]Import{}, map[string]bool{}
	needed := p.requiredLibraries(images, index)
	var unresolved []string
	for _, name := range names {
		library := index[name]
		if weak[name] && !strong[name] && !needed[library] {
			missing[name] = true
			p.WeakZero = append(p.WeakZero, name)
			continue
		}
		if library == "" {
			if weak[name] && !strong[name] {
				missing[name] = true
				p.WeakZero = append(p.WeakZero, name)
				continue
			}
			unresolved = append(unresolved, name)
			continue
		}
		b := Import{Local: fmt.Sprintf("%simport_%d", p.Namespace, len(p.Imports)), Remote: name, Library: library}
		imports[name] = b
		p.Imports = append(p.Imports, b)
	}
	if len(unresolved) != 0 {
		return &UnresolvedError{Names: unresolved}
	}
	for oi, m := range images {
		zeroCell, zeroCall := uint32(0), uint32(0)
		for si := range m.sections {
			s := &m.sections[si]
			if s.flags&elf.SHF_ALLOC == 0 {
				continue
			}
			var out []reloc
			for _, r := range s.relocs {
				t := elf.R_X86_64(r.typ)
				if !amd64Supported(t) {
					return fmt.Errorf("unsupported allocated AMD64 relocation %s in %s", t, s.name)
				}
				if t == elf.R_X86_64_NONE {
					continue
				}
				sym := m.symbols[r.sym]
				width := uint64(4)
				if t == elf.R_X86_64_64 || t == elf.R_X86_64_PC64 {
					width = 8
				}
				if r.off+width > uint64(len(s.data)) || sym.name == "_GLOBAL_OFFSET_TABLE_" || sym.sect == 0 && elf.ST_BIND(sym.info) == elf.STB_LOCAL {
					return fmt.Errorf("invalid AMD64 relocation layout/target")
				}
				if missing[sym.name] {
					switch {
					case t == elf.R_X86_64_64 && r.add == 0:
						binary.LittleEndian.PutUint64(s.data[r.off:], 0)
						continue
					case amd64GOT(t) && r.add == -4:
						if zeroCell == 0 {
							sec := m.addSection(section{name: ".bao.weak_zero", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8)})
							zeroCell = m.addSymbol(fmt.Sprintf("%sweak_zero_%d", p.Namespace, oi), sec, 0, 8)
							s = &m.sections[si]
						}
						// Keep the original MOV/indirect CALL. A plain PC32
						// reference reads the NULL cell without Go GOT relaxation.
						r.typ, r.sym = elf.R_AARCH64(elf.R_X86_64_PC32), zeroCell
					case (t == elf.R_X86_64_PLT32 || t == elf.R_X86_64_PC32) && r.add == -4 && r.off > 0 && (s.data[r.off-1] == 0xe8 || s.data[r.off-1] == 0xe9):
						if zeroCall == 0 {
							code := []byte{0x31, 0xc0, 0xff, 0xe0} // xor eax,eax; jmp rax
							sec := m.addSection(section{name: ".bao.weak_null_call", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 16, size: uint64(len(code)), data: code})
							zeroCall = m.addSymbol(fmt.Sprintf("%sweak_null_call_%d", p.Namespace, oi), sec, 0, uint64(len(code)))
							s = &m.sections[si]
						}
						r.sym = zeroCall
					default:
						return fmt.Errorf("unsupported AMD64 missing-weak reference %s with addend %d", t, r.add)
					}
					out = append(out, r)
					continue
				}
				if b, ok := imports[sym.name]; ok {
					if t == elf.R_X86_64_64 {
						if s.flags&elf.SHF_WRITE == 0 {
							return fmt.Errorf("dynamic absolute pointer must be writable native data")
						}
						name := fmt.Sprintf("%sfixup_%d", p.Namespace, len(p.Fixups))
						m.addSymbol(name, uint16(si), r.off, 8)
						p.Fixups = append(p.Fixups, Fixup{Location: name, Import: b.Local, Addend: r.add})
						binary.LittleEndian.PutUint64(s.data[r.off:], 0)
						continue
					}
					if t == elf.R_X86_64_PC32 || t == elf.R_X86_64_PC64 {
						return fmt.Errorf("external AMD64 PC-relative reference requires GOT or PLT")
					}
				}
				out = append(out, r)
			}
			m.sections[si].relocs = out
		}
		for i := range m.symbols {
			s := &m.symbols[i]
			if b, ok := imports[s.name]; ok {
				s.name, s.info = b.Local, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_NOTYPE)
			} else if missing[s.name] || s.name == "_GLOBAL_OFFSET_TABLE_" {
				s.name, s.info = "bao_missing_weak_unused", byte(elf.STB_LOCAL)<<4|byte(elf.STT_NOTYPE)
			}
		}
		dropTextLabels(m)
	}
	return nil
}
