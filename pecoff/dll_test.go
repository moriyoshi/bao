package pecoff

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

// dllFixture lays out a small PE32+ DLL: .text at 0x1000 (a TLS access, an
// exported function, a TLS callback and DllMain), .rdata at 0x2000 (export,
// import and TLS directories, unwind data), .data at 0x3000 (_tls_index, the
// TLS initializer, the IAT and a pointer), .pdata at 0x4000, .reloc at 0x5000.
type dllFixture struct {
	machine     uint16
	noEvidence  bool
	noRelocs    bool
	exe         bool
	badRelocTyp bool
}

const (
	dllImageBase = 0x180000000
	fxTLSUse     = 0x1000
	fxFn         = 0x1040
	fxCallback   = 0x1050
	fxMain       = 0x1060
	fxExportDir  = 0x2000
	fxImportDir  = 0x2100
	fxTLSDir     = 0x2200
	fxCallbacks  = 0x2240
	fxUnwind     = 0x2300
	fxTLSIndex   = 0x3000
	fxTLSData    = 0x3008
	fxIAT        = 0x3020
	fxPointer    = 0x3040
	fxPdata      = 0x4000
	fxReloc      = 0x5000
)

func (o dllFixture) build() []byte {
	if o.machine == 0 {
		o.machine = pe.IMAGE_FILE_MACHINE_AMD64
	}
	le := binary.LittleEndian
	img := make([]byte, 0x6000)
	put32 := func(rva, v uint32) { le.PutUint32(img[rva:], v) }
	put64 := func(rva uint32, v uint64) { le.PutUint64(img[rva:], v) }
	cstr := func(rva uint32, s string) { copy(img[rva:], s+"\x00") }
	var relocs []uint32
	va := func(rva, target uint32) { put64(rva, dllImageBase+uint64(target)); relocs = append(relocs, rva) }

	// Code.
	if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		p := uint32(fxTLSUse)
		if !o.noEvidence {
			copy(img[p:], []byte{0x8b, 0x0d}) // MOV ECX, [RIP+disp32] (_tls_index)
			put32(p+2, fxTLSIndex-(p+6))
			p += 6
		}
		copy(img[p:], []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0, 0, 0, 0xc3}) // MOV RAX, GS:[0x58]; RET
		img[fxFn], img[fxCallback] = 0xc3, 0xc3
		copy(img[fxMain:], []byte{0xb8, 1, 0, 0, 0, 0xc3})
	} else {
		w := func(rva, v uint32) { put32(rva, v) }
		p := uint32(fxTLSUse)
		if !o.noEvidence {
			page := int64(fxTLSIndex&^0xfff) - int64(p&^0xfff)
			imm := uint32(page >> 12)
			w(p, 0x90000008|(imm&3)<<29|(imm>>2&0x7ffff)<<5)  // ADRP X8, _tls_index
			w(p+4, 0xb9400108|uint32(fxTLSIndex&0xfff/4)<<10) // LDR W8, [X8, #lo12]
			p += 8
		}
		w(p, 0xf9402e49)   // LDR X9, [X18, #0x58]
		w(p+4, 0xd65f03c0) // RET
		w(fxFn, 0xd65f03c0)
		w(fxCallback, 0xd65f03c0)
		w(fxMain, 0x52800020)   // MOV W0, #1
		w(fxMain+4, 0xd65f03c0) // RET
	}

	// Exports: fn, data_value, and a forwarder.
	put32(fxExportDir+20, 3) // NumberOfFunctions
	put32(fxExportDir+24, 3) // NumberOfNames
	put32(fxExportDir+28, fxExportDir+0x40)
	put32(fxExportDir+32, fxExportDir+0x50)
	put32(fxExportDir+36, fxExportDir+0x60)
	put32(fxExportDir+0x40, fxFn)
	put32(fxExportDir+0x44, fxPointer)
	put32(fxExportDir+0x48, fxExportDir+0x90) // forwarder string inside the directory
	for i, n := range []struct {
		rva  uint32
		name string
	}{{fxExportDir + 0x70, "data_value"}, {fxExportDir + 0x80, "fn"}, {fxExportDir + 0x88, "fwd"}} {
		cstr(n.rva, n.name)
		put32(fxExportDir+0x50+uint32(4*i), n.rva)
	}
	le.PutUint16(img[fxExportDir+0x60:], 1) // data_value
	le.PutUint16(img[fxExportDir+0x62:], 0) // fn
	le.PutUint16(img[fxExportDir+0x64:], 2) // fwd
	cstr(fxExportDir+0x90, "OTHER.thing")

	// Imports from kernel32.dll: GetTickCount64 by name, ordinal 5.
	put32(fxImportDir, fxImportDir+0x40)    // OriginalFirstThunk
	put32(fxImportDir+12, fxImportDir+0x80) // Name
	put32(fxImportDir+16, fxIAT)            // FirstThunk
	put64(fxImportDir+0x40, fxImportDir+0x60)
	put64(fxImportDir+0x48, 1<<63|5)
	cstr(fxImportDir+0x62, "GetTickCount64")
	cstr(fxImportDir+0x80, "KERNEL32.dll")
	put64(fxIAT, fxImportDir+0x60)
	put64(fxIAT+8, 1<<63|5)

	// TLS directory and callback list; data pointers carry base relocations.
	va(fxTLSDir, fxTLSData)
	va(fxTLSDir+8, fxTLSData+8)
	va(fxTLSDir+16, fxTLSIndex)
	va(fxTLSDir+24, fxCallbacks)
	put32(fxTLSDir+32, 8)       // SizeOfZeroFill
	put32(fxTLSDir+36, 4<<20)   // 8-byte alignment
	va(fxCallbacks, fxCallback) // null-terminated
	va(fxTLSData, fxFn)         // a pointer in the TLS initializer
	va(fxPointer, fxFn)

	// One function-table entry for fn.
	if o.machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		put32(fxPdata, fxFn)
		put32(fxPdata+4, fxFn+1)
		put32(fxPdata+8, fxUnwind)
		img[fxUnwind] = 1 // UNWIND_INFO version 1
	} else {
		put32(fxPdata, fxFn)
		put32(fxPdata+4, 0x00200001) // packed: 1 instruction, no frame
	}

	// Base relocations, one block per page.
	blocks := map[uint32][]uint16{}
	for _, r := range relocs {
		kind := uint16(10)
		if o.badRelocTyp {
			kind = 3
		}
		blocks[r&^0xfff] = append(blocks[r&^0xfff], kind<<12|uint16(r&0xfff))
	}
	off := uint32(fxReloc)
	for _, page := range []uint32{0x2000, 0x3000} {
		entries := blocks[page]
		if len(entries)%2 != 0 {
			entries = append(entries, 0) // IMAGE_REL_BASED_ABSOLUTE padding
		}
		put32(off, page)
		put32(off+4, uint32(8+2*len(entries)))
		for i, e := range entries {
			le.PutUint16(img[off+8+uint32(2*i):], e)
		}
		off += uint32(8 + 2*len(entries))
	}
	relocSize := off - fxReloc

	// Headers: DOS stub, COFF header, PE32+ optional header, five sections.
	copy(img, "MZ")
	put32(0x3c, 0x40)
	copy(img[0x40:], "PE\x00\x00")
	coff := uint32(0x44)
	le.PutUint16(img[coff:], o.machine)
	le.PutUint16(img[coff+2:], 5)
	le.PutUint16(img[coff+16:], 240)
	chars := uint16(pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_LARGE_ADDRESS_AWARE)
	if !o.exe {
		chars |= imageFileDLL
	}
	le.PutUint16(img[coff+18:], chars)
	opt := coff + 20
	le.PutUint16(img[opt:], 0x20b)
	put32(opt+16, fxMain) // AddressOfEntryPoint
	put64(opt+24, dllImageBase)
	put32(opt+32, 0x1000) // SectionAlignment
	put32(opt+36, 0x200)  // FileAlignment
	put32(opt+56, 0x6000) // SizeOfImage
	put32(opt+60, 0x400)  // SizeOfHeaders
	le.PutUint16(img[opt+68:], 3)
	dll := uint16(pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
	le.PutUint16(img[opt+70:], dll)
	put32(opt+108, 16) // NumberOfRvaAndSizes
	dirs := map[int][2]uint32{
		pe.IMAGE_DIRECTORY_ENTRY_EXPORT:    {fxExportDir, 0xa0},
		pe.IMAGE_DIRECTORY_ENTRY_IMPORT:    {fxImportDir, 40},
		pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION: {fxPdata, 12},
		pe.IMAGE_DIRECTORY_ENTRY_BASERELOC: {fxReloc, relocSize},
		pe.IMAGE_DIRECTORY_ENTRY_TLS:       {fxTLSDir, 40},
	}
	if o.machine == pe.IMAGE_FILE_MACHINE_ARM64 {
		dirs[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION] = [2]uint32{fxPdata, 8}
	}
	if o.noRelocs {
		delete(dirs, pe.IMAGE_DIRECTORY_ENTRY_BASERELOC)
		le.PutUint16(img[coff+18:], chars|pe.IMAGE_FILE_RELOCS_STRIPPED)
	}
	for i, d := range dirs {
		put32(opt+112+uint32(8*i), d[0])
		put32(opt+116+uint32(8*i), d[1])
	}
	sec := opt + 240
	for i, s := range []struct {
		name  string
		chars uint32
	}{
		{".text", pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ},
		{".rdata", pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ},
		{".data", pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE},
		{".pdata", pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ},
		{".reloc", pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_DISCARDABLE},
	} {
		h := sec + uint32(40*i)
		copy(img[h:], s.name)
		rva := uint32(0x1000 * (i + 1))
		put32(h+8, 0x1000)  // VirtualSize
		put32(h+12, rva)    // VirtualAddress
		put32(h+16, 0x1000) // SizeOfRawData
		put32(h+20, rva)    // PointerToRawData: the file mirrors the image
		put32(h+36, s.chars)
	}
	return img
}

func TestParseDLL(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		in := dllFixture{machine: machine}.build()
		if !IsDLL(in) {
			t.Fatal("fixture is not a DLL")
		}
		d, arch, err := parseDLL(in, []string{"fn"})
		if err != nil {
			t.Fatalf("%#x: %v", machine, err)
		}
		if d.ImageBase != dllImageBase || d.ImageSize != 0x6000 || d.Entry != fxMain {
			t.Fatalf("%s image %#x %#x %#x", arch, d.ImageBase, d.ImageSize, d.Entry)
		}
		if len(d.Relocations) != 7 || d.Relocations[0] != fxTLSDir {
			t.Fatalf("%s relocations %#x", arch, d.Relocations)
		}
		want := []DLLImport{{fxIAT, "kernel32.dll", "GetTickCount64", 0}, {fxIAT + 8, "kernel32.dll", "", 5}}
		if len(d.Imports) != 2 || d.Imports[0] != want[0] || d.Imports[1] != want[1] {
			t.Fatalf("%s imports %+v", arch, d.Imports)
		}
		if len(d.Exports) != 2 || d.Exports[0] != (DLLExport{"data_value", fxPointer, false}) || d.Exports[1] != (DLLExport{"fn", fxFn, true}) {
			t.Fatalf("%s exports (the forwarder must be skipped) %+v", arch, d.Exports)
		}
		if len(d.Selected) != 1 || d.Selected[0] != fxFn {
			t.Fatalf("%s selected %+v", arch, d.Selected)
		}
		tls := d.TLS
		if tls == nil || tls.Index != fxTLSIndex || tls.Start != fxTLSData || tls.End != fxTLSData+8 || tls.ZeroFill != 8 || tls.Alignment != 8 || len(tls.Callbacks) != 1 || tls.Callbacks[0] != fxCallback {
			t.Fatalf("%s TLS %+v", arch, tls)
		}
		if len(d.Patches) != 1 || d.Patches[0].Thunk < d.ImageSize || d.Size < d.Patches[0].Thunk+uint32(len(d.Patches[0].Body)) {
			t.Fatalf("%s TLS patches %+v", arch, d.Patches)
		}
		p := d.Patches[0]
		if p.Slot < p.Thunk || p.Slot+8 > p.Thunk+uint32(len(p.Body)) || p.Slot%8 != 0 {
			t.Fatalf("%s thunk slot %#x outside thunk %#x+%d", arch, p.Slot, p.Thunk, len(p.Body))
		}
		if arch == "amd64" {
			if p.Site != fxTLSUse+6 || p.Code[0] != 0xe8 || int64(int32(binary.LittleEndian.Uint32(p.Code[1:]))) != int64(p.Thunk)-int64(p.Site+5) {
				t.Fatalf("amd64 patch %+v", p)
			}
		} else {
			branch := func(at uint32, word uint32) int64 { return int64(at) + int64(int32(word<<6)>>6)*4 }
			if p.Site != fxTLSUse+8 || branch(p.Site, binary.LittleEndian.Uint32(p.Code)) != int64(p.Thunk) {
				t.Fatalf("arm64 patch %+v", p)
			}
			_, _, at := arm64TLSThunkCode(9, true)
			jump := uint32(at)
			if word := binary.LittleEndian.Uint32(p.Body[jump:]); word&0xfc000000 != 0x14000000 || branch(p.Thunk+jump, word) != int64(p.Site+4) {
				t.Fatalf("arm64 thunk does not return after the patched load")
			}
		}
		if binary.LittleEndian.Uint32(d.Image[fxTLSIndex:]) != 0 {
			t.Fatal("_tls_index must select slot 0 of Bao's TLS array")
		}
		if d.FunctionTable.Start != fxPdata || d.FunctionTable.End == fxPdata {
			t.Fatalf("%s function table %+v", arch, d.FunctionTable)
		}
		protect := map[uint32]uint32{}
		for _, r := range d.Protections {
			protect[r.Start] = r.Protect
		}
		if protect[0x1000] != pageExecuteRead || protect[0x2000] != pageReadOnly || protect[0x3000] != pageReadWrite || protect[d.ImageSize] != pageExecuteRead {
			t.Fatalf("%s protections %+v", arch, d.Protections)
		}
	}
}

func TestParseDLLRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		in      []byte
		symbols []string
		want    string
	}{
		"no evidence":   {dllFixture{noEvidence: true}.build(), nil, "no nearby _tls_index"},
		"arm64 no evid": {dllFixture{machine: pe.IMAGE_FILE_MACHINE_ARM64, noEvidence: true}.build(), nil, "no nearby _tls_index"},
		"fixed base":    {dllFixture{noRelocs: true}.build(), nil, "preferred address"},
		"executable":    {dllFixture{exe: true}.build(), nil, "not a DLL"},
		"reloc type":    {dllFixture{badRelocTyp: true}.build(), nil, "base relocation type 3"},
		"missing":       {dllFixture{}.build(), []string{"absent"}, "not exported"},
		"data export":   {dllFixture{}.build(), []string{"data_value"}, "C ABI function"},
		"forwarder":     {dllFixture{}.build(), []string{"fwd"}, "not exported"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseDLL(tc.in, tc.symbols); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTranslateDLLLinksHelper(t *testing.T) {
	for _, machine := range []uint16{pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_ARM64} {
		p, err := TranslateDLL(dllFixture{machine: machine}.build(), Options{Symbols: []string{"fn"}})
		if err != nil {
			t.Fatal(err)
		}
		if p.DLL == nil || !p.Runtime || len(p.Exports) != 0 || p.TLS.Symbol == "" || p.TLS.Size < 16 {
			t.Fatalf("plan %+v %+v", p.DLL != nil, p.TLS)
		}
		// The DLL's TLS sits at template offset 0, where its code expects it.
		var template []byte
		for _, b := range p.Objects {
			o, err := parse(b)
			if err != nil {
				t.Fatal(err)
			}
			for i, name := range o.names {
				if name == p.TLS.Symbol && o.symbols[i].SectionNumber > 0 {
					template = o.sections[o.symbols[i].SectionNumber-1].data[o.symbols[i].Value:]
				}
			}
		}
		if len(template) < 8 || binary.LittleEndian.Uint64(template) != dllImageBase+fxFn {
			t.Fatalf("DLL TLS initializer is not first in the template: % x", template[:min(len(template), 8)])
		}
		other, err := TranslateDLL(dllFixture{machine: machine, noEvidence: false}.build()[:len(dllFixture{}.build())], Options{Symbols: []string{"fn"}})
		if err != nil || other.Namespace != p.Namespace {
			t.Fatalf("namespace is not deterministic: %v", err)
		}
		changed := dllFixture{machine: machine}.build()
		changed[fxFn+8] = 1
		if q, err := TranslateDLL(changed, Options{Symbols: []string{"fn"}}); err != nil || q.Namespace == p.Namespace {
			t.Fatalf("namespace must follow the DLL: %v", err)
		}
	}
}

func TestIsDLLRejectsObjects(t *testing.T) {
	o := &object{machine: pe.IMAGE_FILE_MACHINE_AMD64}
	b, err := o.encode()
	if err != nil || IsDLL(b) || IsDLL(bytes.Repeat([]byte("MZ"), 64)) {
		t.Fatal("COFF objects and garbage are not DLLs")
	}
}
