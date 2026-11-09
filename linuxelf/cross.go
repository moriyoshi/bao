package linuxelf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

type LocalFixup struct {
	Location string `json:"location"`
	Target   string `json:"target"`
	Subtract string `json:"subtract"`
	Addend   int64  `json:"addend"`
	Width    int    `json:"width"`
}

func (p *Plan) lowerTLSForMachine(m *image) error {
	if m.effectiveMachine() == elf.EM_AARCH64 {
		return p.lowerTLS(m)
	}
	return p.lowerDynamicTLS(m)
}

func (p *Plan) lowerDynamicTLS(m *image) error {
	offsets := map[uint16]uint64{}
	alignment := uint64(8)
	var template []byte
	for i, s := range m.sections {
		if s.flags&elf.SHF_TLS == 0 {
			continue
		}
		if (s.typ != elf.SHT_PROGBITS && s.typ != elf.SHT_NOBITS) || len(s.relocs) != 0 {
			return fmt.Errorf("unsupported native TLS template %s", s.name)
		}
		alignment = max(alignment, s.align)
		for uint64(len(template))%s.align != 0 {
			template = append(template, 0)
		}
		offsets[uint16(i)] = uint64(len(template))
		if s.typ == elf.SHT_NOBITS {
			template = append(template, make([]byte, s.size)...)
		} else {
			template = append(template, s.data...)
		}
		m.sections[i].flags &^= elf.SHF_ALLOC | elf.SHF_TLS
	}
	if len(template) == 0 {
		template = make([]byte, 8)
	}
	for uint64(len(template))%alignment != 0 {
		template = append(template, 0)
	}
	p.TLSTemplateSize = uint64(len(template))
	p.TLSTemplateAlignment = alignment
	p.TLSTemplateSymbol = p.Runtime("tls_template")
	for _, sym := range m.symbols {
		if elf.ST_TYPE(sym.info) != elf.STT_TLS || sym.sect == 0 {
			continue
		}
		if _, ok := offsets[sym.sect]; !ok || sym.value > m.sections[sym.sect].size || sym.size > m.sections[sym.sect].size-sym.value {
			return fmt.Errorf("native TLS symbol outside its template section")
		}
	}
	sec := m.addSection(section{name: ".bao.tls_template", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: alignment, size: uint64(len(template)), data: template})
	m.addSymbol(p.TLSTemplateSymbol, sec, 0, uint64(len(template)))
	desc := m.addSection(section{name: ".bao.tls_descriptors", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8})
	type key struct {
		sym uint32
		add int64
		ld  bool
	}
	descriptors := map[key]uint32{}
	index := func(r reloc, ld bool) (uint32, error) {
		s := m.symbols[r.sym]
		base, ok := offsets[s.sect]
		if !ok || elf.ST_TYPE(s.info) != elf.STT_TLS {
			return 0, fmt.Errorf("TLS access requires local image TLS definition")
		}
		offset := int64(base+s.value) + r.add
		if offset < 0 || uint64(offset) >= uint64(len(template)) {
			return 0, fmt.Errorf("TLS offset outside template")
		}
		k := key{r.sym, r.add, ld}
		if old, ok := descriptors[k]; ok {
			return old, nil
		}
		d := &m.sections[desc]
		off := uint64(len(d.data))
		d.data = append(d.data, make([]byte, 16)...)
		if !ld {
			binary.LittleEndian.PutUint64(d.data[off+8:], uint64(offset))
		}
		d.size = uint64(len(d.data))
		idx := m.addSymbol(fmt.Sprintf("%stls_desc_%d", p.Namespace, len(descriptors)), desc, off, 16)
		descriptors[k] = idx
		return idx, nil
	}
	for si := range m.sections {
		s := &m.sections[si]
		if s.flags&elf.SHF_ALLOC == 0 {
			continue
		}
		var rels []reloc
		for _, r := range s.relocs {
			if m.effectiveMachine() == elf.EM_LOONGARCH && (elf.R_LARCH(r.typ) == elf.R_LARCH_RELAX || elf.R_LARCH(r.typ) == elf.R_LARCH_ALIGN) {
				continue
			}
			rels = append(rels, r)
		}
		var out []reloc
		for ri := 0; ri < len(rels); ri++ {
			r := rels[ri]
			if m.effectiveMachine() == elf.EM_X86_64 {
				t := elf.R_X86_64(r.typ)
				if t == elf.R_X86_64_TLSGD || t == elf.R_X86_64_TLSLD {
					if ri+1 >= len(rels) {
						return fmt.Errorf("incomplete AMD64 GD/LD TLS sequence")
					}
					call := rels[ri+1]
					if err := validateAMD64TLSCall(s, r, call, m.symbols, p.tlsResolver(m)); err != nil {
						return err
					}
					operand := r
					operand.add = 0 // The -4 in ELF is the RIP displacement bias.
					idx, err := index(operand, t == elf.R_X86_64_TLSLD)
					if err != nil {
						return err
					}
					r.typ, r.sym = elf.R_AARCH64(elf.R_X86_64_PC32), idx
					out = append(out, r, call)
					ri++
					continue
				}
				if t == elf.R_X86_64_DTPOFF32 || t == elf.R_X86_64_DTPOFF64 {
					if err := foldAMD64TLSOffset(s, r, m.symbols, offsets, uint64(len(template))); err != nil {
						return err
					}
					continue
				}
				if t >= elf.R_X86_64_DTPMOD64 && t <= elf.R_X86_64_TPOFF32 || t == elf.R_X86_64_GOTPC32_TLSDESC || t == elf.R_X86_64_TLSDESC_CALL || t == elf.R_X86_64_TLSDESC {
					return fmt.Errorf("unsupported AMD64 TLS model/relocation %s; requires GD/LD", t)
				}
			}
			if m.effectiveMachine() == elf.EM_LOONGARCH && (elf.R_LARCH(r.typ) == elf.R_LARCH_TLS_GD_PC_HI20 || elf.R_LARCH(r.typ) == elf.R_LARCH_TLS_LD_PC_HI20) {
				if ri+2 >= len(rels) {
					return fmt.Errorf("incomplete LoongArch GD/LD TLS sequence")
				}
				lo, call := rels[ri+1], rels[ri+2]
				callWidth := uint64(8)
				if elf.R_LARCH(call.typ) == elf.R_LARCH_B26 {
					callWidth = 4
				}
				if lo.sym != r.sym || lo.add != r.add || elf.R_LARCH(lo.typ) != elf.R_LARCH_GOT_PC_LO12 || lo.off != r.off+4 || (elf.R_LARCH(call.typ) != elf.R_LARCH_CALL36 && elf.R_LARCH(call.typ) != elf.R_LARCH_B26) || (call.off < lo.off+4 || call.off > lo.off+32) || call.add != 0 || m.symbols[call.sym].name != p.tlsResolver(m) || call.off+callWidth > uint64(len(s.data)) {
					return fmt.Errorf("unsupported LoongArch GD/LD TLS relocation sequence at %s: %#v %#v %#v (%s)", s.name, r, lo, call, m.symbols[call.sym].name)
				}
				if binary.LittleEndian.Uint32(s.data[r.off:])&0xfe000000 != 0x1a000000 || binary.LittleEndian.Uint32(s.data[lo.off:])&0xffc003e0 != (0x02c00000|(binary.LittleEndian.Uint32(s.data[r.off:])&31)<<5) {
					return fmt.Errorf("unsupported LoongArch GD/LD TLS instructions at %s %#x: %#x %#x", s.name, r.off, binary.LittleEndian.Uint32(s.data[r.off:]), binary.LittleEndian.Uint32(s.data[lo.off:]))
				}
				if elf.R_LARCH(call.typ) == elf.R_LARCH_B26 {
					opcode := binary.LittleEndian.Uint32(s.data[call.off:]) & 0xfc000000
					if opcode != 0x50000000 && opcode != 0x54000000 {
						return fmt.Errorf("unsupported LoongArch TLS resolver branch instruction")
					}
				}
				// LLVM's local-dynamic form addresses one symbol's descriptor
				// directly; unlike PPC64, it has no subsequent DTPREL offset.
				idx, err := index(r, false)
				if err != nil {
					return err
				}
				r.sym = idx
				r.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_HI20)
				r.add = 0
				lo.sym = idx
				lo.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_LO12)
				lo.add = 0
				out = append(out, r, lo, call)
				ri += 2
				continue
			}
			if m.effectiveMachine() == elf.EM_PPC64 {
				t := elf.R_PPC64(r.typ)
				if t == elf.R_PPC64_GOT_TLSGD16_HA || t == elf.R_PPC64_GOT_TLSLD16_HA {
					if ri+3 >= len(rels) {
						return fmt.Errorf("incomplete PowerPC GD/LD TLS sequence")
					}
					lo, mark, call := rels[ri+1], rels[ri+2], rels[ri+3]
					ld := t == elf.R_PPC64_GOT_TLSLD16_HA
					wantLo, wantMark := elf.R_PPC64_GOT_TLSGD16_LO, elf.R_PPC64_TLSGD
					if ld {
						wantLo, wantMark = elf.R_PPC64_GOT_TLSLD16_LO, elf.R_PPC64_TLSLD
					}
					// GNU .reloc and compiler-produced markers can place these
					// two same-address records in either symbol-table order.
					if elf.R_PPC64(mark.typ) == elf.R_PPC64_REL24 && elf.R_PPC64(call.typ) == wantMark {
						mark, call = call, mark
					}
					if lo.sym != r.sym || lo.add != r.add || elf.R_PPC64(lo.typ) != wantLo || lo.off <= r.off || lo.off-r.off > 64 || mark.sym != r.sym || mark.add != r.add || elf.R_PPC64(mark.typ) != wantMark || (call.off < lo.off+4 || call.off > lo.off+64) || mark.off != call.off || elf.R_PPC64(call.typ) != elf.R_PPC64_REL24 || call.add != 0 || m.symbols[call.sym].name != p.tlsResolver(m) || call.off+4 > uint64(len(s.data)) {
						return fmt.Errorf("unsupported PowerPC GD/LD TLS relocation sequence at %s: %#v %#v %#v %#v (%s)", s.name, r, lo, mark, call, m.symbols[call.sym].name)
					}
					if binary.LittleEndian.Uint32(s.data[r.off:])&0xfc1f0000 != 0x3c020000 || binary.LittleEndian.Uint32(s.data[lo.off:])&0xfc1f0000 != (0x38000000|(binary.LittleEndian.Uint32(s.data[r.off:])>>21&31)<<16) {
						return fmt.Errorf("unsupported PowerPC GD/LD TLS instructions at %s: %#x %#x", s.name, binary.LittleEndian.Uint32(s.data[r.off:]), binary.LittleEndian.Uint32(s.data[lo.off:]))
					}
					idx, err := index(r, ld)
					if err != nil {
						return err
					}
					r.sym = idx
					r.typ = elf.R_AARCH64(elf.R_PPC64_TOC16_HA)
					r.add = 0
					lo.sym = idx
					lo.typ = elf.R_AARCH64(elf.R_PPC64_TOC16_LO)
					lo.add = 0
					out = append(out, r, lo, call)
					ri += 3
					continue
				}
				if t == elf.R_PPC64_DTPREL16_HA || t == elf.R_PPC64_DTPREL16_LO || t == elf.R_PPC64_DTPREL16_LO_DS {
					sym := m.symbols[r.sym]
					base, ok := offsets[sym.sect]
					offset := int64(base+sym.value) + r.add
					if !ok || elf.ST_TYPE(sym.info) != elf.STT_TLS || offset < 0 || uint64(offset) >= uint64(len(template)) || r.off+2 > uint64(len(s.data)) {
						return fmt.Errorf("invalid PowerPC local-dynamic TLS offset")
					}
					value := uint16(offset)
					if t == elf.R_PPC64_DTPREL16_HA {
						value = uint16((offset + 0x8000) >> 16)
					}
					if t == elf.R_PPC64_DTPREL16_LO_DS {
						if offset&3 != 0 {
							return fmt.Errorf("unaligned PowerPC DS TLS offset")
						}
						value = value&0xfffc | binary.LittleEndian.Uint16(s.data[r.off:])&3
					}
					binary.LittleEndian.PutUint16(s.data[r.off:], value)
					continue
				}
			}
			if elf.ST_TYPE(m.symbols[r.sym].info) == elf.STT_TLS {
				return fmt.Errorf("unsupported native TLS reference %d on %s", r.typ, m.arch())
			}
			out = append(out, r)
		}
		m.sections[si].relocs = out
	}
	p.TLSDescriptors = len(descriptors)
	return nil
}

func (p *Plan) anchor(m *image, oi int, sect uint16) string {
	if m.anchors == nil {
		m.anchors = map[uint16]string{}
	}
	if name, ok := m.anchors[sect]; ok {
		return name
	}
	name := fmt.Sprintf("%sanchor_%d_%d", p.Namespace, oi, sect)
	m.addSymbol(name, sect, 0, m.sections[sect].size)
	m.anchors[sect] = name
	return name
}

func (p *Plan) localDifference(m *image, oi, si int, off uint64, a, b uint32, add int64, width int) error {
	s := &m.sections[si]
	if s.flags&elf.SHF_EXECINSTR != 0 || off+uint64(width) > uint64(len(s.data)) || (width != 4 && width != 8) {
		return fmt.Errorf("unsupported native difference fixup layout")
	}
	to, from := m.symbols[a], m.symbols[b]
	if to.sect == 0 || from.sect == 0 || int(to.sect) >= len(m.sections) || int(from.sect) >= len(m.sections) {
		return fmt.Errorf("native difference needs defined section symbols")
	}
	name := fmt.Sprintf("%slocal_fixup_%d", p.Namespace, len(p.LocalFixups))
	m.addSymbol(name, uint16(si), off, uint64(width))
	target := p.anchor(m, oi, to.sect)
	subtract := p.anchor(m, oi, from.sect)
	p.LocalFixups = append(p.LocalFixups, LocalFixup{Location: name, Target: target, Subtract: subtract, Addend: add + int64(to.value) - int64(from.value), Width: width})
	s = &m.sections[si]
	s.flags |= elf.SHF_WRITE
	for i := uint64(0); i < uint64(width); i++ {
		s.data[off+i] = 0
	}
	return nil
}

func (p *Plan) normalizeCross(m *image, oi int) error {
	if m.effectiveMachine() == elf.EM_AARCH64 {
		return nil
	}
	for si := range m.sections {
		s := &m.sections[si]
		if s.flags&elf.SHF_ALLOC == 0 {
			continue
		}
		var out []reloc
		for i := 0; i < len(s.relocs); i++ {
			r := s.relocs[i]
			if m.effectiveMachine() == elf.EM_LOONGARCH && elf.R_LARCH(r.typ) == elf.R_LARCH_CALL36 {
				// Go 1.26.10's CALL36 emitter sign-extends the high immediate
				// into opcode bits for backward calls. Express the same call
				// with supported B26 plus a retained NOP slot. Returning at
				// PC+4 executes that slot before the original PC+8 continuation.
				if r.off+8 > uint64(len(s.data)) {
					return fmt.Errorf("truncated LoongArch CALL36")
				}
				hi, lo := binary.LittleEndian.Uint32(s.data[r.off:]), binary.LittleEndian.Uint32(s.data[r.off+4:])
				if hi&0xfe000000 != 0x1e000000 || lo&0xfc000000 != 0x4c000000 || lo>>5&31 != hi&31 || (lo&31 != 0 && lo&31 != 1) || lo&31 == 0 && hi&31 == 1 {
					return fmt.Errorf("unsupported LoongArch CALL36 instruction pair")
				}
				word := uint32(0x50000000)
				if lo&31 == 1 {
					word = 0x54000000
				}
				binary.LittleEndian.PutUint32(s.data[r.off:], word)
				binary.LittleEndian.PutUint32(s.data[r.off+4:], 0x03400000)
				r.typ = elf.R_AARCH64(elf.R_LARCH_B26)
				out = append(out, r)
				continue
			}
			if m.effectiveMachine() == elf.EM_PPC64 && elf.R_PPC64(r.typ) == elf.R_PPC64_REL64 || m.effectiveMachine() == elf.EM_LOONGARCH && (elf.R_LARCH(r.typ) == elf.R_LARCH_32_PCREL || elf.R_LARCH(r.typ) == elf.R_LARCH_64_PCREL) {
				width := 8
				if m.effectiveMachine() == elf.EM_LOONGARCH && elf.R_LARCH(r.typ) == elf.R_LARCH_32_PCREL {
					width = 4
				}
				place := m.addSymbol(fmt.Sprintf("%spcrel_%d", p.Namespace, len(p.LocalFixups)), uint16(si), r.off, uint64(width))
				if err := p.localDifference(m, oi, si, r.off, r.sym, place, r.add, width); err != nil {
					return err
				}
				s = &m.sections[si]
				continue
			}
			if m.effectiveMachine() == elf.EM_LOONGARCH {
				t := elf.R_LARCH(r.typ)
				if t == elf.R_LARCH_ADD_ULEB128 {
					if i+1 >= len(s.relocs) {
						return fmt.Errorf("unpaired ULEB difference")
					}
					q := s.relocs[i+1]
					a, b := m.symbols[r.sym], m.symbols[q.sym]
					if q.off != r.off || elf.R_LARCH(q.typ) != elf.R_LARCH_SUB_ULEB128 || a.sect == 0 || a.sect != b.sect {
						return fmt.Errorf("cross-section ULEB difference unsupported")
					}
					old, n := binary.Uvarint(s.data[r.off:])
					if n <= 0 {
						return fmt.Errorf("invalid difference ULEB")
					}
					v := int64(old) + int64(a.value) - int64(b.value) + r.add - q.add
					if v < 0 {
						return fmt.Errorf("negative ULEB difference")
					}
					u := uint64(v)
					for j := 0; j < n; j++ {
						value := byte(u & 127)
						u >>= 7
						if j+1 < n {
							value |= 128
						}
						s.data[int(r.off)+j] = value
					}
					if u != 0 {
						return fmt.Errorf("ULEB difference exceeds reserved width")
					}
					i++
					continue
				}
				width, bits := 0, 0
				var sub elf.R_LARCH
				switch t {
				case elf.R_LARCH_ADD6:
					width, bits, sub = 1, 6, elf.R_LARCH_SUB6
				case elf.R_LARCH_ADD8:
					width, bits, sub = 1, 8, elf.R_LARCH_SUB8
				case elf.R_LARCH_ADD16:
					width, bits, sub = 2, 16, elf.R_LARCH_SUB16
				case elf.R_LARCH_ADD32:
					width, bits, sub = 4, 32, elf.R_LARCH_SUB32
				case elf.R_LARCH_ADD64:
					width, bits, sub = 8, 64, elf.R_LARCH_SUB64
				}
				if width != 0 {
					if i+1 >= len(s.relocs) {
						return fmt.Errorf("unpaired LoongArch difference")
					}
					q := s.relocs[i+1]
					if q.off != r.off || elf.R_LARCH(q.typ) != sub || r.off+uint64(width) > uint64(len(s.data)) {
						return fmt.Errorf("unsupported LoongArch difference pair")
					}
					a, b := m.symbols[r.sym], m.symbols[q.sym]
					old := uint64(0)
					for j := 0; j < width; j++ {
						old |= uint64(s.data[int(r.off)+j]) << uint(8*j)
					}
					if a.sect != b.sect || a.sect == 0 {
						if err := p.localDifference(m, oi, si, r.off, r.sym, q.sym, int64(old)+r.add-q.add, width); err != nil {
							return err
						}
						s = &m.sections[si]
					} else {
						value := old + uint64(int64(a.value)-int64(b.value)+r.add-q.add)
						if bits == 6 {
							value = value&63 | old&192
						}
						for j := 0; j < width; j++ {
							s.data[int(r.off)+j] = byte(value >> uint(8*j))
						}
					}
					i++
					continue
				}
				if t == elf.R_LARCH_ALIGN || t == elf.R_LARCH_RELAX {
					continue
				}
			}
			out = append(out, r)
		}
		m.sections[si].relocs = out
	}
	return nil
}

func supportedCross(machine elf.Machine, t elf.R_AARCH64) bool {
	if machine == elf.EM_LOONGARCH {
		switch elf.R_LARCH(t) {
		case elf.R_LARCH_NONE, elf.R_LARCH_64, elf.R_LARCH_B16, elf.R_LARCH_B21, elf.R_LARCH_B26, elf.R_LARCH_CALL36, elf.R_LARCH_PCALA_HI20, elf.R_LARCH_PCALA_LO12, elf.R_LARCH_GOT_PC_HI20, elf.R_LARCH_GOT_PC_LO12:
			return true
		}
	}
	if machine == elf.EM_PPC64 {
		switch elf.R_PPC64(t) {
		case elf.R_PPC64_NONE, elf.R_PPC64_ADDR64, elf.R_PPC64_REL24, elf.R_PPC64_REL32, elf.R_PPC64_REL16_HA, elf.R_PPC64_REL16_LO, elf.R_PPC64_TOC16_HA, elf.R_PPC64_TOC16_LO, elf.R_PPC64_TOC16_DS, elf.R_PPC64_TOC16_LO_DS:
			return true
		}
	}
	return false
}

func (p *Plan) bindCross(images []*image, index map[string]string) error {
	defined, strong, weak := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range images {
		for _, s := range m.symbols {
			if elf.ST_BIND(s.info) == elf.STB_LOCAL || s.name == ".TOC." {
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
	for n := range strong {
		if !defined[n] {
			names = append(names, n)
		}
	}
	for n := range weak {
		if !defined[n] && !strong[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	bindings := map[string]Import{}
	missing := map[string]bool{}
	needed := p.requiredLibraries(images, index)
	var unresolved []string
	for _, n := range names {
		lib := index[n]
		if weak[n] && !strong[n] && !needed[lib] {
			missing[n] = true
			p.WeakZero = append(p.WeakZero, n)
			continue
		}
		if lib == "" {
			if weak[n] && !strong[n] {
				missing[n] = true
				p.WeakZero = append(p.WeakZero, n)
				continue
			}
			unresolved = append(unresolved, n)
			continue
		}
		b := Import{Local: fmt.Sprintf("%simport_%d", p.Namespace, len(p.Imports)), Remote: n, Library: lib}
		bindings[n] = b
		p.Imports = append(p.Imports, b)
	}
	if len(unresolved) != 0 {
		return &UnresolvedError{Names: unresolved}
	}
	for oi, m := range images {
		for si := range m.sections {
			s := &m.sections[si]
			if s.flags&elf.SHF_ALLOC == 0 {
				continue
			}
			var out []reloc
			for _, r := range s.relocs {
				if !supportedCross(m.effectiveMachine(), r.typ) {
					return fmt.Errorf("unsupported allocated %s relocation %d in %s", m.arch(), r.typ, s.name)
				}
				if r.typ == 0 {
					continue
				}
				sym := m.symbols[r.sym]
				absolute := m.effectiveMachine() == elf.EM_LOONGARCH && elf.R_LARCH(r.typ) == elf.R_LARCH_64 || m.effectiveMachine() == elf.EM_PPC64 && elf.R_PPC64(r.typ) == elf.R_PPC64_ADDR64
				if missing[sym.name] {
					if r.add != 0 {
						return fmt.Errorf("nonzero addend for unavailable weak %s", sym.name)
					}
					if m.effectiveMachine() == elf.EM_LOONGARCH && (elf.R_LARCH(r.typ) == elf.R_LARCH_CALL36 || elf.R_LARCH(r.typ) == elf.R_LARCH_B26) || m.effectiveMachine() == elf.EM_PPC64 && elf.R_PPC64(r.typ) == elf.R_PPC64_REL24 {
						name := fmt.Sprintf("%sweak_null_call_%d", p.Namespace, oi)
						idx := uint32(0)
						for j, q := range m.symbols {
							if q.name == name {
								idx = uint32(j)
							}
						}
						if idx == 0 {
							words := []uint32{0x4c000000}
							if m.effectiveMachine() == elf.EM_PPC64 {
								words = []uint32{0x39800000, 0x7d8903a6, 0x4e800420}
							}
							var code []byte
							for _, word := range words {
								code = binary.LittleEndian.AppendUint32(code, word)
							}
							sec := m.addSection(section{name: ".bao.weak_null_call", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: uint64(len(code)), data: code})
							idx = m.addSymbol(name, sec, 0, uint64(len(code)))
							s = &m.sections[si]
						}
						r.sym = idx
						out = append(out, r)
						continue
					}
					if absolute {
						binary.LittleEndian.PutUint64(s.data[r.off:], 0)
						continue
					}
					if m.effectiveMachine() == elf.EM_LOONGARCH && (elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_HI20 || elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_LO12) {
						name := fmt.Sprintf("%sweak_zero_%d", p.Namespace, oi)
						idx := uint32(0)
						for j, q := range m.symbols {
							if q.name == name {
								idx = uint32(j)
							}
						}
						if idx == 0 {
							sec := m.addSection(section{name: ".bao.weak_zero", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_WRITE, align: 8, size: 8, data: make([]byte, 8)})
							idx = m.addSymbol(name, sec, 0, 8)
							s = &m.sections[si]
						}
						r.sym = idx
						if elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_HI20 {
							r.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_HI20)
						} else {
							r.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_LO12)
						}
						out = append(out, r)
						continue
					}
					return fmt.Errorf("unsupported reference to missing weak %s (reloc %d)", sym.name, r.typ)
				}
				if b, ok := bindings[sym.name]; ok && absolute {
					if s.flags&elf.SHF_WRITE == 0 || r.off+8 > uint64(len(s.data)) {
						return fmt.Errorf("dynamic absolute pointer must be writable native data")
					}
					name := fmt.Sprintf("%sfixup_%d", p.Namespace, len(p.Fixups))
					m.addSymbol(name, uint16(si), r.off, 8)
					p.Fixups = append(p.Fixups, Fixup{Location: name, Import: b.Local, Addend: r.add})
					binary.LittleEndian.PutUint64(s.data[r.off:], 0)
					continue
				}
				if m.effectiveMachine() == elf.EM_LOONGARCH && sym.sect != 0 && (elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_HI20 || elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_LO12) {
					if r.off+4 > uint64(len(s.data)) {
						return fmt.Errorf("GOT instruction outside code")
					}
					if elf.R_LARCH(r.typ) == elf.R_LARCH_GOT_PC_HI20 {
						r.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_HI20)
					} else {
						word := binary.LittleEndian.Uint32(s.data[r.off:])
						if word&0xffc00000 != 0x28c00000 {
							return fmt.Errorf("unexpected LoongArch local GOT load")
						}
						binary.LittleEndian.PutUint32(s.data[r.off:], 0x02c00000|word&0x003fffff)
						r.typ = elf.R_AARCH64(elf.R_LARCH_PCALA_LO12)
					}
				}
				out = append(out, r)
			}
			m.sections[si].relocs = out
		}
		for i := range m.symbols {
			s := &m.symbols[i]
			if b, ok := bindings[s.name]; ok {
				s.name = b.Local
				s.info = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE)
			} else if missing[s.name] {
				s.name = "bao_missing_weak_unused"
				s.info = byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE)
			}
		}
		dropTextLabels(m)
	}
	return nil
}

// Internal branch labels must remain relocation identities without contributing
// thousands of zero-length entries to Go's native function table.
func dropTextLabels(m *image) {
	anchors := map[uint16]uint32{}
	for i, s := range m.symbols {
		if elf.ST_TYPE(s.info) == elf.STT_SECTION {
			anchors[s.sect] = uint32(i)
		}
	}
	replace := map[uint32]struct {
		sym uint32
		add uint64
	}{}
	for i := 1; i < len(m.symbols); i++ {
		s := m.symbols[i]
		if s.sect == 0 || elf.ST_BIND(s.info) != elf.STB_LOCAL || elf.ST_TYPE(s.info) != elf.STT_NOTYPE || m.sections[s.sect].flags&elf.SHF_EXECINSTR == 0 || !strings.HasPrefix(s.name, ".L") {
			continue
		}
		anchor, ok := anchors[s.sect]
		if !ok {
			anchor = uint32(len(m.symbols))
			m.symbols = append(m.symbols, symbol{info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_SECTION), sect: s.sect})
			anchors[s.sect] = anchor
		}
		replace[uint32(i)] = struct {
			sym uint32
			add uint64
		}{anchor, s.value}
		m.symbols[i] = symbol{name: "bao_discarded_label", info: byte(elf.STB_LOCAL)<<4 | byte(elf.STT_NOTYPE)}
	}
	for si := range m.sections {
		for ri := range m.sections[si].relocs {
			r := &m.sections[si].relocs[ri]
			if q, ok := replace[r.sym]; ok {
				r.sym = q.sym
				r.add += int64(q.add)
			}
		}
	}
}

func (p *Plan) tlsResolver(m *image) string {
	if m.effectiveMachine() == elf.EM_PPC64 {
		return p.Runtime("tls_resolver")
	}
	return p.Runtime("tls_lookup")
}
