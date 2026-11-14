package linuxelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

// soFixture describes a small AArch64 shared object: a read-only executable
// segment holding the dynamic metadata, code and unwind tables, and a
// writable segment at rw holding .dynamic, .init_array, GOT slots, data and
// the TLS initializer.
type soFixture struct {
	codeEnd  uint64 // end of the executable segment's memory
	rw       uint64
	pie      bool
	textrel  bool
	extra    []dynReloc
	noShdrs  bool
	exportTL bool
}

const (
	soText     = 0x800
	soEHFrame  = 0x900
	soEHHdr    = 0x980
	soDynsym   = 0x200
	soDynstr   = 0x300
	soRela     = 0x400
	soDynSize  = 0xc0
	soInitOff  = soDynSize        // .init_array
	soGOT      = soInitOff + 8    // GLOB_DAT puts
	soDesc     = soGOT + 8        // TLSDESC pair
	soPtr      = soDesc + 16      // RELATIVE -> obj
	soObj      = soPtr + 8        // exported obj
	soTData    = soObj + 8        // TLS initializer, RELATIVE -> fn
	soFileSize = soTData + 8 + 16 // a little trailing data
)

func (o soFixture) build() []byte {
	if o.codeEnd == 0 {
		o.codeEnd = 0x1000
	}
	if o.rw == 0 {
		o.rw = 0x20000
	}
	le := binary.LittleEndian
	rx := make([]byte, 0x1000)
	rwData := make([]byte, soFileSize)
	strtab := []byte("\x00puts\x00fn\x00obj\x00tv\x00")
	copy(rx[soDynstr:], strtab)
	sym := func(i int, name uint32, info byte, shndx uint16, value, size uint64) {
		b := rx[soDynsym+24*i:]
		le.PutUint32(b, name)
		b[4] = info
		le.PutUint16(b[6:], shndx)
		le.PutUint64(b[8:], value)
		le.PutUint64(b[16:], size)
	}
	tvBind := elf.STB_LOCAL
	if o.exportTL {
		tvBind = elf.STB_GLOBAL
	}
	sym(1, 1, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_FUNC), 0, 0, 0)            // puts
	sym(2, 6, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_FUNC), 4, soText, 8)       // fn
	sym(3, 9, byte(elf.STB_GLOBAL)<<4|byte(elf.STT_OBJECT), 9, o.rw+soObj, 8) // obj
	sym(4, 13, byte(tvBind)<<4|byte(elf.STT_TLS), 8, 8, 8)                    // tv, TLS offset 8
	le.PutUint32(rx[soText:], 0xd65f03c0)                                     // ret
	le.PutUint32(rx[soText+4:], 0xd65f03c0)                                   // ret
	le.PutUint32(rx[soEHFrame:], 0)                                           // terminator only
	copy(rx[soEHHdr:], []byte{1, 0x1b, 0x03, 0x3b})                           // version, pcrel|sdata4
	delta := int32(soEHFrame - (soEHHdr + 4))
	le.PutUint32(rx[soEHHdr+4:], uint32(delta)) // eh_frame_ptr
	relocs := []dynReloc{
		{off: o.rw + soInitOff, typ: elf.R_AARCH64_RELATIVE, add: soText},
		{off: o.rw + soGOT, typ: elf.R_AARCH64_GLOB_DAT, sym: 1},
		{off: o.rw + soDesc, typ: elf.R_AARCH64_TLSDESC, sym: 4},
		{off: o.rw + soPtr, typ: elf.R_AARCH64_RELATIVE, add: int64(o.rw + soObj)},
		{off: o.rw + soTData, typ: elf.R_AARCH64_RELATIVE, add: soText + 4},
	}
	if o.textrel {
		relocs = append(relocs, dynReloc{off: soText, typ: elf.R_AARCH64_RELATIVE})
	}
	relocs = append(relocs, o.extra...)
	for i, r := range relocs {
		b := rx[soRela+24*i:]
		le.PutUint64(b, r.off)
		le.PutUint64(b[8:], uint64(r.sym)<<32|uint64(r.typ))
		le.PutUint64(b[16:], uint64(r.add))
	}
	dyn := [][2]uint64{
		{uint64(elf.DT_RELA), soRela}, {uint64(elf.DT_RELASZ), uint64(24 * len(relocs))}, {uint64(elf.DT_RELAENT), 24},
		{uint64(elf.DT_SYMTAB), soDynsym}, {uint64(elf.DT_STRTAB), soDynstr}, {uint64(elf.DT_STRSZ), uint64(len(strtab))}, {uint64(elf.DT_SYMENT), 24},
		{uint64(elf.DT_INIT_ARRAY), o.rw + soInitOff}, {uint64(elf.DT_INIT_ARRAYSZ), 8},
	}
	if o.pie {
		dyn = append(dyn, [2]uint64{uint64(elf.DT_FLAGS_1), uint64(elf.DF_1_PIE)})
	}
	for i, d := range dyn {
		le.PutUint64(rwData[16*i:], d[0])
		le.PutUint64(rwData[16*i+8:], d[1])
	}

	// File: ELF header and program headers inside the first page, the
	// writable segment's bytes at 0x1000, then section headers.
	out := append([]byte{}, rx...)
	out = append(out, rwData...)
	shoff := uint64(len(out))
	type shdr struct {
		name            string
		typ             elf.SectionType
		flags           elf.SectionFlag
		addr, off, size uint64
		link, info      uint32
		align, entsize  uint64
	}
	shdrs := []shdr{{},
		{".dynsym", elf.SHT_DYNSYM, elf.SHF_ALLOC, soDynsym, soDynsym, 5 * 24, 2, 4, 8, 24},
		{".dynstr", elf.SHT_STRTAB, elf.SHF_ALLOC, soDynstr, soDynstr, uint64(len(strtab)), 0, 0, 1, 0},
		{".rela.dyn", elf.SHT_RELA, elf.SHF_ALLOC, soRela, soRela, uint64(24 * len(relocs)), 1, 0, 8, 24},
		{".text", elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_EXECINSTR, soText, soText, 8, 0, 0, 4, 0},
		{".eh_frame", elf.SHT_PROGBITS, elf.SHF_ALLOC, soEHFrame, soEHFrame, 4, 0, 0, 8, 0},
		{".eh_frame_hdr", elf.SHT_PROGBITS, elf.SHF_ALLOC, soEHHdr, soEHHdr, 12, 0, 0, 4, 0},
		{".dynamic", elf.SHT_DYNAMIC, elf.SHF_ALLOC | elf.SHF_WRITE, o.rw, 0x1000, soDynSize, 2, 0, 8, 16},
		{".tdata", elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS, o.rw + soTData, 0x1000 + soTData, 8, 0, 0, 8, 0},
		{".data", elf.SHT_PROGBITS, elf.SHF_ALLOC | elf.SHF_WRITE, o.rw + soInitOff, 0x1000 + soInitOff, soTData - soInitOff, 0, 0, 8, 0},
		{".shstrtab", elf.SHT_STRTAB, 0, 0, 0, 0, 0, 0, 1, 0},
	}
	if o.noShdrs {
		shdrs = shdrs[:1]
	}
	var names []byte
	nameOff := make([]uint32, len(shdrs))
	for i, s := range shdrs {
		nameOff[i] = uint32(len(names))
		names = append(append(names, s.name...), 0)
	}
	shstr := uint64(len(out)) + uint64(64*len(shdrs))
	if !o.noShdrs {
		shdrs[len(shdrs)-1].off, shdrs[len(shdrs)-1].size = shstr, uint64(len(names))
	}
	for i, s := range shdrs {
		b := make([]byte, 64)
		if i > 0 {
			le.PutUint32(b, nameOff[i])
			le.PutUint32(b[4:], uint32(s.typ))
			le.PutUint64(b[8:], uint64(s.flags))
			le.PutUint64(b[16:], s.addr)
			le.PutUint64(b[24:], s.off)
			le.PutUint64(b[32:], s.size)
			le.PutUint32(b[40:], s.link)
			le.PutUint32(b[44:], s.info)
			le.PutUint64(b[48:], s.align)
			le.PutUint64(b[56:], s.entsize)
		}
		out = append(out, b...)
	}
	out = append(out, names...)

	copy(out, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(out[16:], uint16(elf.ET_DYN))
	le.PutUint16(out[18:], uint16(elf.EM_AARCH64))
	le.PutUint32(out[20:], 1)
	le.PutUint64(out[32:], 64) // phoff
	le.PutUint64(out[40:], shoff)
	le.PutUint16(out[52:], 64)
	le.PutUint16(out[54:], 56)
	phdrs := []elf.ProgHeader{
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0, Vaddr: 0, Filesz: 0x1000, Memsz: o.codeEnd, Align: 0x10000},
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Off: 0x1000, Vaddr: o.rw, Filesz: soFileSize, Memsz: 0x200, Align: 0x10000},
		{Type: elf.PT_DYNAMIC, Flags: elf.PF_R | elf.PF_W, Off: 0x1000, Vaddr: o.rw, Filesz: soDynSize, Memsz: soDynSize, Align: 8},
		{Type: elf.PT_TLS, Flags: elf.PF_R, Off: 0x1000 + soTData, Vaddr: o.rw + soTData, Filesz: 8, Memsz: 16, Align: 8},
		{Type: elf.PT_GNU_RELRO, Flags: elf.PF_R, Off: 0x1000, Vaddr: o.rw, Filesz: soObj, Memsz: soObj, Align: 1},
		{Type: elf.PT_GNU_EH_FRAME, Flags: elf.PF_R, Off: soEHHdr, Vaddr: soEHHdr, Filesz: 12, Memsz: 12, Align: 4},
	}
	le.PutUint16(out[56:], uint16(len(phdrs)))
	le.PutUint16(out[58:], 64)
	le.PutUint16(out[60:], uint16(len(shdrs)))
	le.PutUint16(out[62:], uint16(len(shdrs)-1))
	for i, p := range phdrs {
		b := out[64+56*i:]
		le.PutUint32(b, uint32(p.Type))
		le.PutUint32(b[4:], uint32(p.Flags))
		le.PutUint64(b[8:], p.Off)
		le.PutUint64(b[16:], p.Vaddr)
		le.PutUint64(b[24:], p.Vaddr)
		le.PutUint64(b[32:], p.Filesz)
		le.PutUint64(b[40:], p.Memsz)
		le.PutUint64(b[48:], p.Align)
	}
	return out
}

func TestDelinkSharedObject(t *testing.T) {
	in := soFixture{}.build()
	if !IsSharedObject(in) {
		t.Fatal("fixture is not ET_DYN")
	}
	d, err := delink(in, "t_")
	if err != nil {
		t.Fatal(err)
	}
	m, info := d.m, d.info
	blob := m.sections[1]
	if blob.flags != elf.SHF_ALLOC|elf.SHF_EXECINSTR || blob.align != 4096 || uint64(len(blob.data)) != 0x20200+sharedObjectPad || info.ImageSize != uint64(len(blob.data)) {
		t.Fatalf("image section %+v", blob.flags)
	}
	if binary.LittleEndian.Uint32(blob.data[soText:]) != 0xd65f03c0 {
		t.Fatal("code not carried at its image offset")
	}
	want := map[uint64]reloc{
		0x20000 + soInitOff: {typ: elf.R_AARCH64_ABS64, sym: 1, add: soText},
		0x20000 + soPtr:     {typ: elf.R_AARCH64_ABS64, sym: 1, add: 0x20000 + soObj},
		0x20000 + soTData:   {typ: elf.R_AARCH64_ABS64, sym: 1, add: soText + 4},
		0x20000 + soDesc:    {typ: elf.R_AARCH64_TLSDESC, add: 8},
		0x20200:             {typ: elf.R_AARCH64_ABS64, sym: 1}, // PIE check
	}
	for _, r := range blob.relocs {
		if r.off == 0x20000+soGOT {
			if s := m.symbols[r.sym]; s.name != "puts" || s.sect != 0 || r.typ != elf.R_AARCH64_ABS64 {
				t.Fatalf("GLOB_DAT import became %+v against %+v", r, s)
			}
			continue
		}
		w, ok := want[r.off]
		if !ok || r.typ != w.typ || r.add != w.add || (w.sym != 0 && r.sym != w.sym) {
			t.Fatalf("unexpected image relocation %+v", r)
		}
		if r.typ == elf.R_AARCH64_TLSDESC && (m.symbols[r.sym].sect == 0 || m.sections[m.symbols[r.sym].sect].flags&elf.SHF_TLS == 0) {
			t.Fatal("TLS descriptor does not name the TLS template")
		}
		delete(want, r.off)
	}
	if len(want) != 0 {
		t.Fatalf("missing image relocations %+v", want)
	}
	var tdata, init *section
	for i := range m.sections {
		switch m.sections[i].name {
		case ".tdata":
			tdata = &m.sections[i]
		case ".init_array":
			init = &m.sections[i]
		}
	}
	if tdata == nil || tdata.size != 16 || len(tdata.relocs) != 1 || tdata.relocs[0].off != 0 || tdata.relocs[0].add != soText+4 {
		t.Fatalf("TLS initializer pointer not relocated in the template: %+v", tdata)
	}
	if init == nil || init.typ != elf.SHT_INIT_ARRAY || len(init.relocs) != 1 || init.relocs[0].add != soText {
		t.Fatalf("constructor table %+v", init)
	}
	if len(info.Exports) != 2 || info.Exports[0] != (Export{"fn", "func", soText, 8}) || info.Exports[1] != (Export{"obj", "object", 0x20000 + soObj, 8}) {
		t.Fatalf("exports %+v", info.Exports)
	}
	if info.MaxPageSize != 65536 || len(info.Writable) != 1 || info.Writable[0] != (Range{0x20000, 0x20200}) || len(info.RELRO) != 1 || info.RELRO[0] != (Range{0x20000, 0x20000 + soObj}) {
		t.Fatalf("protection plan %+v %+v %+v", info.MaxPageSize, info.Writable, info.RELRO)
	}
	if info.CheckOffset != 0x20200 {
		t.Fatalf("base check at %#x", info.CheckOffset)
	}
	if d.ehFrame != soEHFrame {
		t.Fatalf("unwind table at %#x", d.ehFrame)
	}
}

func TestDelinkLimitsPageSizeToSegmentGaps(t *testing.T) {
	d, err := delink(soFixture{codeEnd: 0x1c000}.build(), "t_")
	if err != nil || d.info.MaxPageSize != 16384 {
		t.Fatalf("16 KiB gap: %v %+v", err, d)
	}
	if _, err := delink(soFixture{codeEnd: 0x1f800}.build(), "t_"); err == nil || !strings.Contains(err.Error(), "within 4 KiB of executable code") {
		t.Fatalf("2 KiB gap accepted: %v", err)
	}
}

func TestDelinkRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		o    soFixture
		want string
	}{
		"text relocation": {soFixture{textrel: true}, "text relocations are unsupported"},
		"ifunc":           {soFixture{extra: []dynReloc{{off: 0x20000 + soObj + 8, typ: elf.R_AARCH64_IRELATIVE}}}, "indirect functions"},
		"initial-exec":    {soFixture{extra: []dynReloc{{off: 0x20000 + soObj + 8, typ: elf.R_AARCH64_TLS_TPREL64, sym: 4}}}, "only TLS descriptors"},
		"overlap":         {soFixture{extra: []dynReloc{{off: 0x20000 + soPtr, typ: elf.R_AARCH64_RELATIVE}}}, "overlapping"},
		"tls address":     {soFixture{extra: []dynReloc{{off: 0x20000 + soObj + 8, typ: elf.R_AARCH64_ABS64, sym: 4}}}, "thread-local"},
		"pie":             {soFixture{pie: true}, "position-independent executable"},
		"no headers":      {soFixture{noShdrs: true}, "section headers"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := delink(tc.o.build(), "t_"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A shared object's TLS descriptor slot becomes a Bao descriptor in place,
// and its GOT import a fixup addressed from the image base.
func TestSharedObjectTLSAndImportLowering(t *testing.T) {
	d, err := delink(soFixture{}.build(), "test_")
	if err != nil {
		t.Fatal(err)
	}
	m := d.m
	p := &Plan{Namespace: "test_", SharedObject: d.info}
	if err := p.lowerTLS(m); err != nil {
		t.Fatal(err)
	}
	if p.TLSDescriptors != 1 || p.TLSTemplateSize != 16 {
		t.Fatalf("descriptors %d template %d", p.TLSDescriptors, p.TLSTemplateSize)
	}
	blob := &m.sections[1]
	if got := binary.LittleEndian.Uint64(blob.data[0x20000+soDesc+8:]); got != 8 {
		t.Fatalf("descriptor offset %d", got)
	}
	if err := p.bind([]*image{m, thunkHelper()}, map[string]string{"puts": "libc.so.6"}); err != nil {
		t.Fatal(err)
	}
	if len(p.Fixups) != 1 || p.Fixups[0] != (Fixup{Location: "test_so_base", Offset: 0x20000 + soGOT, Import: "test_import_0"}) {
		t.Fatalf("fixups %+v", p.Fixups)
	}
	for _, r := range blob.relocs {
		if r.off == 0x20000+soDesc && m.symbols[r.sym].name != "test_tls_thunk" {
			t.Fatalf("descriptor resolver %s", m.symbols[r.sym].name)
		}
	}
	var template *section
	for i := range m.sections {
		if m.sections[i].name == ".bao.tls_template" {
			template = &m.sections[i]
		}
	}
	if template == nil || len(template.relocs) != 1 || template.relocs[0].sym != 1 || template.relocs[0].add != soText+4 {
		t.Fatalf("template pointer %+v", template)
	}
}

func TestMergeKeepsRelocatableInputReferences(t *testing.T) {
	d, err := delink(soFixture{}.build(), "t_")
	if err != nil {
		t.Fatal(err)
	}
	glue := &image{sections: []section{{}, {name: ".text", typ: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, align: 4, size: 4, data: make([]byte, 4), relocs: []reloc{{off: 0, sym: 2, typ: elf.R_AARCH64_CALL26}}}},
		symbols: []symbol{{}, {name: "glue", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1, size: 4}, {name: "fn", info: byte(elf.STB_GLOBAL) << 4}}}
	sections, symbols := len(d.m.sections), len(d.m.symbols)
	if err := d.m.merge(glue); err != nil {
		t.Fatal(err)
	}
	g := d.m.sections[sections]
	if g.name != ".text" || d.m.symbols[g.relocs[0].sym].name != "fn" || d.m.symbols[symbols].sect != uint16(sections) {
		t.Fatal("merged references renumbered incorrectly")
	}
	dup := &image{sections: []section{{}, {name: ".text", flags: elf.SHF_ALLOC}}, symbols: []symbol{{}, {name: "fn", info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), sect: 1}}}
	if err := d.m.merge(dup); err == nil || !strings.Contains(err.Error(), "defined by both") {
		t.Fatalf("duplicate definition accepted: %v", err)
	}
}

func TestIsSharedObjectRejectsRelocatable(t *testing.T) {
	m := &image{sections: []section{{}}, symbols: []symbol{{}}}
	b, err := m.encode()
	if err != nil || IsSharedObject(b) || IsSharedObject(bytes.Repeat([]byte{0}, 64)) {
		t.Fatal("relocatable or garbage input reported as a shared object")
	}
}
