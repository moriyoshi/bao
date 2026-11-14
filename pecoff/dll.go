package pecoff

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"go/token"
	"sort"
	"strings"
)

// A linked DLL reaches its own code and data through PC-relative instructions
// that no longer carry relocations, and Go's PE reader gives host code only
// function alignment, while ARM64 ADRP needs the image's 4 KiB page offsets.
// Bao therefore carries the DLL's prepared image as package data and loads it
// at initialization into memory from VirtualAlloc, as the Windows loader
// would: base relocations, imports by name or ordinal, section protections,
// TLS, its function table and DllMain.
//
// Code outside every Windows image keeps unwind lookup simple: a function
// table registered with the DLL's own base is found for its addresses (the
// executable's static exception directory takes precedence only for code
// inside the executable), so every personality routine's image-relative data
// stays valid. RtlPcToFileHeader reports no image there, which breaks MSVC's
// C++ throw; the helper replaces the DLL's imports of it and of
// _CxxThrowException to report the DLL's base instead.

// DLLImage describes a DLL loaded by the generated package.
type DLLImage struct {
	SHA256      string
	ImageBase   uint64
	Size        uint32 // the image, then TLS thunks
	ImageSize   uint32
	Entry       uint32
	Relocations []uint32
	Imports     []DLLImport
	Protections []DLLRange
	Exports     []DLLExport
	// Selected holds the image offsets of the -symbol exports, in order.
	Selected      []uint32
	FunctionTable DLLRange
	TLS           *DLLTLS
	Patches       []DLLPatch
	Image         []byte `json:"-"`
}

// DLLImport is one import address table slot.
type DLLImport struct {
	Slot    uint32
	DLL     string
	Name    string `json:",omitempty"`
	Ordinal uint16 `json:",omitempty"`
}

// DLLRange is a half-open range of image offsets with a page protection.
type DLLRange struct {
	Start, End uint32
	Protect    uint32 `json:",omitempty"`
}

// DLLExport is an exported name.
type DLLExport struct {
	Name     string
	RVA      uint32
	Function bool
}

// DLLTLS describes implicit TLS. Index locates the DLL's _tls_index, which
// selects the slot of Bao's one-slot TLS array: zero.
type DLLTLS struct {
	Index, Start, End, ZeroFill, Alignment uint32
	Callbacks                              []uint32
	// Relocated reports base relocations inside the initializer, whose
	// loaded bytes then replace the template's.
	Relocated bool
}

// DLLPatch redirects one TEB TLS-array load to a thunk at Thunk. Site holds
// the replacement instruction bytes; Slot is the thunk's helper address cell.
type DLLPatch struct {
	Site  uint32
	Code  []byte
	Thunk uint32
	Body  []byte
	Slot  uint32
}

const (
	pageNoAccess         = 0x01
	pageReadOnly         = 0x02
	pageReadWrite        = 0x04
	pageExecuteRead      = 0x20
	imageFileDLL         = 0x2000
	imageRelBasedAbs     = 0
	imageRelBasedDir64   = 10
	dllMaxImage          = 512 << 20
	dllTLSEvidenceWindow = 64
)

// IsDLL reports whether input is a PE DLL image.
func IsDLL(input []byte) bool {
	if len(input) < 2 || input[0] != 'M' || input[1] != 'Z' {
		return false
	}
	f, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Characteristics&imageFileDLL != 0
}

// DLLMachine reports a DLL's Go architecture.
func DLLMachine(input []byte) (string, error) {
	f, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64", nil
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64", nil
	}
	return "", fmt.Errorf("unsupported DLL machine %#x; Windows targets are amd64/arm64", f.Machine)
}

func parseDLL(input []byte, symbols []string) (*DLLImage, string, error) {
	f, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	arch, err := DLLMachine(input)
	if err != nil {
		return nil, "", err
	}
	if f.Characteristics&imageFileDLL == 0 {
		return nil, "", fmt.Errorf("input is a Windows executable, not a DLL")
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, "", fmt.Errorf("requires a 64-bit (PE32+) DLL")
	}
	if oh.SizeOfImage == 0 || oh.SizeOfImage > dllMaxImage || oh.SectionAlignment < 4096 || oh.SectionAlignment&(oh.SectionAlignment-1) != 0 || oh.SizeOfHeaders > oh.SizeOfImage {
		return nil, "", fmt.Errorf("unsupported DLL image layout (size %#x, section alignment %#x)", oh.SizeOfImage, oh.SectionAlignment)
	}
	dir := func(i int) (uint32, uint32) {
		if i >= int(oh.NumberOfRvaAndSizes) {
			return 0, 0
		}
		return oh.DataDirectory[i].VirtualAddress, oh.DataDirectory[i].Size
	}
	if rva, _ := dir(pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR); rva != 0 {
		return nil, "", fmt.Errorf(".NET assemblies are unsupported")
	}
	page := func(n uint32) uint32 { return (n + 4095) &^ 4095 }
	img := make([]byte, page(oh.SizeOfImage))
	raw := func(off, n uint32) ([]byte, error) {
		if uint64(off)+uint64(n) > uint64(len(input)) {
			return nil, fmt.Errorf("DLL file data outside the file")
		}
		return input[off : off+n], nil
	}
	headers, err := raw(0, min(oh.SizeOfHeaders, uint32(len(input))))
	if err != nil {
		return nil, "", err
	}
	copy(img, headers)
	d := &DLLImage{ImageBase: oh.ImageBase, ImageSize: uint32(len(img)), Entry: oh.AddressOfEntryPoint}
	sum := sha256.Sum256(input)
	d.SHA256 = fmt.Sprintf("%x", sum)
	d.Protections = append(d.Protections, DLLRange{0, page(oh.SizeOfHeaders), pageReadOnly})
	var code []span
	for _, s := range f.Sections {
		size := max(s.VirtualSize, s.Size)
		if s.VirtualSize != 0 {
			size = s.VirtualSize
		}
		end := uint64(s.VirtualAddress) + uint64(page(size))
		if s.VirtualAddress%4096 != 0 || end > uint64(len(img)) {
			return nil, "", fmt.Errorf("DLL section %s outside the image", s.Name)
		}
		if s.Characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0 && s.Size != 0 {
			data, err := raw(s.Offset, min(s.Size, size))
			if err != nil {
				return nil, "", err
			}
			copy(img[s.VirtualAddress:], data)
		}
		protect := uint32(pageReadOnly)
		switch {
		case s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 && s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0:
			return nil, "", fmt.Errorf("writable executable DLL section %s is unsupported", s.Name)
		case s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0:
			protect = pageExecuteRead
			code = append(code, span{s.VirtualAddress, s.VirtualAddress + size})
		case s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0:
			protect = pageReadWrite
		case s.Characteristics&pe.IMAGE_SCN_MEM_READ == 0:
			protect = pageNoAccess
		}
		d.Protections = append(d.Protections, DLLRange{s.VirtualAddress, uint32(end), protect})
	}
	in := func(rva uint32, n uint64) bool { return uint64(rva)+n <= uint64(oh.SizeOfImage) }
	u32 := func(rva uint32) uint32 { return binary.LittleEndian.Uint32(img[rva:]) }
	u64 := func(rva uint32) uint64 { return binary.LittleEndian.Uint64(img[rva:]) }
	cstring := func(rva uint32) (string, error) {
		if !in(rva, 1) {
			return "", fmt.Errorf("DLL string outside the image")
		}
		end := bytes.IndexByte(img[rva:], 0)
		if end < 0 || end > 4096 {
			return "", fmt.Errorf("unterminated DLL string")
		}
		return string(img[rva : int(rva)+end]), nil
	}
	if d.Entry != 0 && !inSpans(code, d.Entry) {
		return nil, "", fmt.Errorf("DLL entry point outside code")
	}

	// Base relocations: only 64-bit absolute slots appear in PE32+ images.
	if rva, size := dir(pe.IMAGE_DIRECTORY_ENTRY_BASERELOC); size != 0 {
		if !in(rva, uint64(size)) {
			return nil, "", fmt.Errorf("DLL base relocations outside the image")
		}
		for off := rva; off+8 <= rva+size; {
			pageRVA, block := u32(off), u32(off+4)
			if block < 8 || block%2 != 0 || off+block > rva+size {
				return nil, "", fmt.Errorf("malformed DLL base relocation block at %#x", off)
			}
			for e := off + 8; e < off+block; e += 2 {
				entry := binary.LittleEndian.Uint16(img[e:])
				switch entry >> 12 {
				case imageRelBasedAbs:
				case imageRelBasedDir64:
					slot := pageRVA + uint32(entry&0xfff)
					if !in(slot, 8) {
						return nil, "", fmt.Errorf("DLL base relocation at %#x outside the image", slot)
					}
					d.Relocations = append(d.Relocations, slot)
				default:
					return nil, "", fmt.Errorf("unsupported DLL base relocation type %d", entry>>12)
				}
			}
			off += block
		}
	} else if f.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED != 0 || oh.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
		return nil, "", fmt.Errorf("DLL has no base relocations, so it can load only at its preferred address")
	}
	sort.Slice(d.Relocations, func(i, j int) bool { return d.Relocations[i] < d.Relocations[j] })

	// Imports, by name or ordinal. A bound import table is ignored: every
	// slot is resolved again.
	if rva, size := dir(pe.IMAGE_DIRECTORY_ENTRY_IMPORT); size != 0 {
		for desc := rva; ; desc += 20 {
			if !in(desc, 20) {
				return nil, "", fmt.Errorf("DLL import descriptors outside the image")
			}
			lookup, name, iat := u32(desc), u32(desc+12), u32(desc+16)
			if name == 0 && iat == 0 {
				break
			}
			lib, err := cstring(name)
			if err != nil {
				return nil, "", err
			}
			if !validDLL(lib) {
				return nil, "", fmt.Errorf("invalid DLL import library %q", lib)
			}
			if lookup == 0 {
				lookup = iat
			}
			for i := uint32(0); ; i += 8 {
				if !in(lookup+i, 8) || !in(iat+i, 8) {
					return nil, "", fmt.Errorf("DLL import table outside the image")
				}
				v := u64(lookup + i)
				if v == 0 {
					break
				}
				im := DLLImport{Slot: iat + i, DLL: strings.ToLower(lib)}
				if v&(1<<63) != 0 {
					im.Ordinal = uint16(v)
				} else if im.Name, err = cstring(uint32(v) + 2); err != nil {
					return nil, "", err
				}
				d.Imports = append(d.Imports, im)
			}
		}
	}

	// Exports. Forwarders name another DLL's export and have no code here.
	if rva, size := dir(pe.IMAGE_DIRECTORY_ENTRY_EXPORT); size != 0 {
		if !in(rva, 40) {
			return nil, "", fmt.Errorf("DLL export directory outside the image")
		}
		functions, names, addresses, nameRVAs, ordinals := u32(rva+20), u32(rva+24), u32(rva+28), u32(rva+32), u32(rva+36)
		if !in(addresses, 4*uint64(functions)) || !in(nameRVAs, 4*uint64(names)) || !in(ordinals, 2*uint64(names)) {
			return nil, "", fmt.Errorf("DLL export tables outside the image")
		}
		for i := uint32(0); i < names; i++ {
			name, err := cstring(u32(nameRVAs + 4*i))
			if err != nil {
				return nil, "", err
			}
			index := uint32(binary.LittleEndian.Uint16(img[ordinals+2*i:]))
			if index >= functions {
				return nil, "", fmt.Errorf("DLL export %s has an invalid ordinal", name)
			}
			target := u32(addresses + 4*index)
			if target >= rva && target < rva+size || !in(target, 1) {
				continue
			}
			d.Exports = append(d.Exports, DLLExport{name, target, inSpans(code, target)})
		}
		sort.Slice(d.Exports, func(i, j int) bool { return d.Exports[i].Name < d.Exports[j].Name })
	}
	for _, name := range symbols {
		i := sort.Search(len(d.Exports), func(i int) bool { return d.Exports[i].Name >= name })
		if i == len(d.Exports) || d.Exports[i].Name != name {
			return nil, "", fmt.Errorf("selected export %q is not exported by the DLL", name)
		}
		if !d.Exports[i].Function || !token.IsIdentifier(name) {
			return nil, "", fmt.Errorf("selected DLL export %q must be an undecorated C ABI function", name)
		}
		d.Selected = append(d.Selected, d.Exports[i].RVA)
	}

	if rva, size := dir(pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION); size != 0 {
		width := uint32(12)
		if arch == "arm64" {
			width = 8
		}
		if size%width != 0 || !in(rva, uint64(size)) {
			return nil, "", fmt.Errorf("malformed DLL exception directory")
		}
		d.FunctionTable = DLLRange{Start: rva, End: rva + size}
	}

	// Implicit TLS: the TEB's TLS array load is redirected to Bao's helper.
	size := uint32(len(img))
	if rva, dsize := dir(pe.IMAGE_DIRECTORY_ENTRY_TLS); dsize != 0 {
		if !in(rva, 40) {
			return nil, "", fmt.Errorf("DLL TLS directory outside the image")
		}
		va := func(off uint32) (uint32, error) {
			v := u64(rva + off)
			if v < oh.ImageBase || v-oh.ImageBase >= uint64(oh.SizeOfImage) {
				return 0, fmt.Errorf("DLL TLS directory address outside the image")
			}
			return uint32(v - oh.ImageBase), nil
		}
		t := &DLLTLS{ZeroFill: u32(rva + 32), Alignment: 1}
		if bits := u32(rva+36) >> 20 & 15; bits != 0 {
			t.Alignment = 1 << (bits - 1)
		}
		if t.Start, err = va(0); err != nil {
			return nil, "", err
		}
		if t.End, err = va(8); err != nil {
			return nil, "", err
		}
		if t.Index, err = va(16); err != nil {
			return nil, "", err
		}
		if t.End < t.Start || !in(t.Index, 4) || t.ZeroFill > 64<<20 {
			return nil, "", fmt.Errorf("malformed DLL TLS directory")
		}
		if u64(rva+24) != 0 {
			list, err := va(24)
			if err != nil {
				return nil, "", err
			}
			for p := list; ; p += 8 {
				if !in(p, 8) {
					return nil, "", fmt.Errorf("DLL TLS callbacks outside the image")
				}
				cb := u64(p)
				if cb == 0 {
					break
				}
				if cb < oh.ImageBase || !inSpans(code, uint32(cb-oh.ImageBase)) {
					return nil, "", fmt.Errorf("DLL TLS callback outside code")
				}
				t.Callbacks = append(t.Callbacks, uint32(cb-oh.ImageBase))
			}
		}
		binary.LittleEndian.PutUint32(img[t.Index:], 0)
		for _, r := range d.Relocations {
			t.Relocated = t.Relocated || r+8 > t.Start && r < t.End
		}
		d.TLS = t
		for _, c := range code {
			patches, err := patchDLLTLSReads(img, c.start, min(c.end, oh.SizeOfImage), t.Index, arch, &size)
			if err != nil {
				return nil, "", err
			}
			d.Patches = append(d.Patches, patches...)
		}
		// MinGW's CRT has a TLS directory even when GCC's emulated TLS leaves
		// no TLS array load to patch.
	}
	d.Size = (size + 4095) &^ 4095
	if len(d.Patches) != 0 {
		d.Protections = append(d.Protections, DLLRange{d.ImageSize, d.Size, pageExecuteRead})
	}
	d.Image = img
	return d, arch, nil
}

type span struct{ start, end uint32 }

func inSpans(spans []span, rva uint32) bool {
	for _, s := range spans {
		if rva >= s.start && rva < s.end {
			return true
		}
	}
	return false
}

// patchDLLTLSReads finds the TEB ThreadLocalStoragePointer load (amd64
// MOV r64, GS:[0x58]; arm64 LDR Xn, [X18, #0x58]) in a DLL's code. A linked
// DLL keeps no relocation marking it, so each match must have a PC-relative
// reference that decodes to the DLL's _tls_index within 64 bytes, as the
// compiler's TLS access sequence does. Thunks follow the image, starting at
// *end, which advances.
func patchDLLTLSReads(img []byte, start, stop, index uint32, arch string, end *uint32) ([]DLLPatch, error) {
	var patches []DLLPatch
	evidence := func(pos uint32) bool {
		lo, hi := uint32(0), pos+dllTLSEvidenceWindow
		if pos > start+dllTLSEvidenceWindow {
			lo = pos - dllTLSEvidenceWindow
		} else {
			lo = start
		}
		hi = min(hi, stop)
		if arch == "amd64" {
			// A RIP-relative disp32 is followed by 0, 1 or 4 immediate bytes.
			for q := lo; q+4 <= hi; q++ {
				disp := int64(int32(binary.LittleEndian.Uint32(img[q:])))
				for _, tail := range []int64{0, 1, 4} {
					if int64(q)+4+tail+disp == int64(index) {
						return true
					}
				}
			}
			return false
		}
		// ADRP Xr, page(_tls_index), then LDR Wt, [Xr, #lo12].
		for q := lo &^ 3; q+4 <= hi; q += 4 {
			w := binary.LittleEndian.Uint32(img[q:])
			if w&0x9f000000 != 0x90000000 {
				continue
			}
			imm := int64(w>>29&3) | int64(w>>5&0x7ffff)<<2
			imm = imm << 43 >> 43 // sign-extend 21 bits
			if uint64(int64(q)&^0xfff+imm<<12) != uint64(index)&^0xfff {
				continue
			}
			for l := q + 4; l+4 <= min(q+4+dllTLSEvidenceWindow, stop); l += 4 {
				v := binary.LittleEndian.Uint32(img[l:])
				if v&0xffc00000 == 0xb9400000 && v>>5&31 == w&31 && (v>>10&0xfff)*4 == index&0xfff {
					return true
				}
			}
		}
		return false
	}
	for pos := start; pos < stop; pos++ {
		reg, width := -1, uint32(9)
		if arch == "amd64" {
			if pos+9 <= stop && img[pos] == 0x65 && (img[pos+1] == 0x48 || img[pos+1] == 0x4c) && img[pos+2] == 0x8b && img[pos+3]&0xc7 == 4 && img[pos+4] == 0x25 && binary.LittleEndian.Uint32(img[pos+5:]) == 0x58 {
				reg = int((img[pos+3]>>3)&7) | int((img[pos+1]&4)<<1)
			}
		} else {
			width = 4
			if pos%4 == 0 && pos+4 <= stop && binary.LittleEndian.Uint32(img[pos:])&0xffffffe0 == 0xf9402e40 {
				reg = int(img[pos] & 31)
			}
		}
		if reg < 0 {
			continue
		}
		if !evidence(pos) {
			lo, hi := start, min(stop, pos+dllTLSEvidenceWindow)
			if pos > start+dllTLSEvidenceWindow {
				lo = (pos - dllTLSEvidenceWindow) &^ 3
			}
			return nil, fmt.Errorf("DLL TLS array load at %#x has no nearby reference to _tls_index at %#x; code %#x-%#x: % x", pos, index, lo, hi, img[lo:hi])
		}
		thunk := (*end + 15) &^ 15
		p := DLLPatch{Site: pos, Thunk: thunk}
		if arch == "amd64" {
			if reg == 4 {
				return nil, fmt.Errorf("unsupported DLL TLS load into the stack pointer at %#x", pos)
			}
			body, call := amd64TLSThunkCode(reg, true)
			p.Body = body
			p.Slot = thunk + uint32(call+6) + binary.LittleEndian.Uint32(body[call+2:])
			p.Code = []byte{0xe8, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90}
			binary.LittleEndian.PutUint32(p.Code[1:], thunk-(pos+5))
		} else {
			if reg > 17 {
				return nil, fmt.Errorf("unsupported DLL TLS array register x%d at %#x", reg, pos)
			}
			body, _, jump := arm64TLSThunkCode(reg, true)
			back := int64(pos+4) - int64(thunk+uint32(jump))
			forward := int64(thunk) - int64(pos)
			if back < -1<<27 || forward >= 1<<27 {
				return nil, fmt.Errorf("DLL image too large for TLS thunk branches")
			}
			binary.LittleEndian.PutUint32(body[jump:], 0x14000000|uint32(back>>2)&0x3ffffff)
			p.Body = body
			p.Slot = thunk + uint32(len(body)) - 8
			p.Code = binary.LittleEndian.AppendUint32(nil, 0x14000000|uint32(forward>>2)&0x3ffffff)
		}
		*end = thunk + uint32(len(p.Body))
		patches = append(patches, p)
		pos += width - 1
	}
	return patches, nil
}

// TranslateDLL plans a DLL for loading by the generated package. The helper
// supplies TLS storage and the C++ throw adapters; a small anchor object
// selects it through the ordinary COFF translation.
func TranslateDLL(input []byte, opts Options) (*Plan, error) {
	d, arch, err := parseDLL(input, opts.Symbols)
	if err != nil {
		return nil, err
	}
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	ret, abs := []byte{0xc3, 0xcc, 0xcc, 0xcc}, uint16(1) // IMAGE_REL_AMD64_ADDR64
	if arch == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
		ret, abs = []byte{0xc0, 0x03, 0x5f, 0xd6}, 14 // IMAGE_REL_ARM64_ADDR64
	}
	o := &object{machine: machine}
	o.sections = append(o.sections, section{name: ".text", flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ | 0x500000, size: 4, data: ret})
	o.addSymbol(dllAnchor, 1, 0)
	o.symbols[len(o.symbols)-1].Type = 0x20
	helpers := []string{"bao_winrt_tls_array", "bao_winrt_dll_configure", "bao_winrt_pc_to_file_header", "bao_winrt_cxx_throw"}
	refs := section{name: ".data", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | 0x400000, size: uint32(8 * len(helpers)), data: make([]byte, 8*len(helpers))}
	for i, name := range helpers {
		refs.relocs = append(refs.relocs, pe.Reloc{VirtualAddress: uint32(8 * i), SymbolTableIndex: uint32(len(o.symbols)), Type: abs})
		o.addSymbol(name, 0, 0)
		o.symbols[len(o.symbols)-1].Type = 0x20
	}
	o.sections = append(o.sections, refs)
	// The DLL's digest makes this anchor, and so the package namespace,
	// distinct for each DLL.
	sum := sha256.Sum256(input)
	o.sections = append(o.sections, section{name: ".rdata", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | 0x100000, size: 32, data: sum[:]})
	if t := d.TLS; t != nil {
		// The DLL's TLS goes first in Bao's template, at the offsets its code
		// uses: ".tls" sorts before the helper's ".tls$" contributions.
		if t.Alignment > 8192 {
			return nil, fmt.Errorf("DLL TLS alignment exceeds 8192")
		}
		bits := uint32(1)
		for 1<<(bits-1) < t.Alignment {
			bits++
		}
		data := append(append([]byte(nil), d.Image[t.Start:t.End]...), make([]byte, t.ZeroFill)...)
		if len(data) == 0 {
			data = make([]byte, 8)
		}
		o.sections = append(o.sections, section{name: ".tls", flags: pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | bits<<20, size: uint32(len(data)), data: data})
	}
	anchor, err := o.encode()
	if err != nil {
		return nil, err
	}
	sub := opts
	sub.Symbols = []string{dllAnchor}
	p, err := Translate(anchor, sub)
	if err != nil {
		return nil, err
	}
	if !p.Runtime || p.Arch != arch {
		return nil, fmt.Errorf("Bao's Windows helper was not linked for the DLL")
	}
	p.Exports = nil
	p.DLL = d
	return p, nil
}

const dllAnchor = "bao_dll_anchor"
