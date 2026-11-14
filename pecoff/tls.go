package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Each thunk preserves the interrupted native instruction's registers and flags.
// Lifecycle callbacks and nonlocal TLS initializers must not throw; allocation
// failure terminates through Windows fail-fast. Exceptions stay in native callers.
func (o *object) patchTLSReads(si int, arch string) (int, error) {
	count := 0
	length := len(o.sections[si].data)
	for pos := 0; pos < length; pos++ {
		data := o.sections[si].data
		reg := -1
		width := 9
		if arch == "amd64" {
			if pos+9 <= length && data[pos] == 0x65 && (data[pos+1] == 0x48 || data[pos+1] == 0x4c) && data[pos+2] == 0x8b && data[pos+3]&0xc7 == 4 && data[pos+4] == 0x25 && binary.LittleEndian.Uint32(data[pos+5:]) == 0x58 {
				reg = int((data[pos+3]>>3)&7) | int((data[pos+1]&4)<<1)
				if reg == 4 {
					return 0, fmt.Errorf("unsupported native TLS load into stack pointer")
				}
			}
		} else {
			width = 4
			if pos%4 == 0 && pos+4 <= length && binary.LittleEndian.Uint32(data[pos:])&0xffffffe0 == 0xf9402e40 {
				reg = int(data[pos] & 31)
				if reg > 17 {
					return 0, fmt.Errorf("unsupported native TLS array register x%d", reg)
				}
			}
		}
		if reg < 0 {
			continue
		}
		// Tie the recognized TEB instruction to the compiler's TLS index access,
		// rather than accepting an unrelated TEB instruction elsewhere in the object.
		indexNear := false
		for _, r := range o.sections[si].relocs {
			if o.names[r.SymbolTableIndex] == "_tls_index" && int(r.VirtualAddress) >= pos-64 && int(r.VirtualAddress) <= pos+64 {
				indexNear = true
			}
			if int(r.VirtualAddress) >= pos && int(r.VirtualAddress) < pos+width {
				return 0, fmt.Errorf("relocation overlaps native TLS array instruction")
			}
		}
		if !indexNear {
			return 0, fmt.Errorf("native TLS array load has no nearby _tls_index access")
		}
		name := fmt.Sprintf("bao_tls_thunk_%d_%d", si, pos)
		target := uint32(len(o.symbols))
		o.addSymbol(name, int16(len(o.sections)+1), 0)
		o.symbols[target].StorageClass = 3
		o.symbols[target].Type = 0x20
		helper := uint32(len(o.symbols))
		o.addSymbol("bao_winrt_tls_array", 0, 0)
		o.symbols[helper].Type = 0x20
		var thunk section
		if arch == "amd64" {
			thunk = amd64TLSThunk(reg, helper)
			copy(data[pos:pos+9], []byte{0xe8, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90})
			o.sections[si].relocs = append(o.sections[si].relocs, pe.Reloc{VirtualAddress: uint32(pos + 1), SymbolTableIndex: target, Type: 4})
		} else {
			back := uint32(len(o.symbols))
			o.addSymbol(name+"_return", int16(si+1), uint32(pos+4))
			o.symbols[back].StorageClass = 3
			thunk = arm64TLSThunk(reg, helper, back)
			binary.LittleEndian.PutUint32(data[pos:], 0x14000000)
			o.sections[si].relocs = append(o.sections[si].relocs, pe.Reloc{VirtualAddress: uint32(pos), SymbolTableIndex: target, Type: 3})
		}
		o.sections = append(o.sections, thunk)
		count++
		pos += width - 1
	}
	return count, nil
}

func amd64TLSThunk(reg int, helper uint32) section {
	code, call := amd64TLSThunkCode(reg, false)
	return section{name: ".text", flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ | 0x500000, size: uint32(len(code)), data: code, relocs: []pe.Reloc{{VirtualAddress: uint32(call + 1), SymbolTableIndex: helper, Type: 4}}}
}

// amd64TLSThunkCode returns the thunk and the offset of its helper call. An
// indirect thunk calls through an 8-byte slot after its RET, which the loader
// of a private DLL image fills: the image may be beyond a rel32 call's reach.
func amd64TLSThunkCode(reg int, indirect bool) ([]byte, int) {
	var code []byte
	regs := []int{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	code = append(code, 0x9c) // PUSHFQ
	for _, r := range regs {
		if r >= 8 {
			code = append(code, 0x41)
		}
		code = append(code, 0x50+byte(r&7))
	}
	// RBP points at the complete saved register frame; align the C call stack.
	code = append(code, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x81, 0xec, 0x80, 0, 0, 0)
	for r := 0; r < 6; r++ {
		code = append(code, 0xf3, 0x0f, 0x7f, byte(0x44|r<<3), 0x24, byte(32+16*r))
	}
	call := len(code)
	if indirect {
		code = append(code, 0xff, 0x15, 0, 0, 0, 0) // CALL [RIP+slot]
	} else {
		code = append(code, 0xe8, 0, 0, 0, 0)
	}
	for i, r := range regs {
		if r == reg {
			code = append(code, 0x48, 0x89, 0x45, byte((len(regs)-1-i)*8))
		}
	}
	for r := 0; r < 6; r++ {
		code = append(code, 0xf3, 0x0f, 0x6f, byte(0x44|r<<3), 0x24, byte(32+16*r))
	}
	code = append(code, 0x48, 0x89, 0xec)
	for i := len(regs) - 1; i >= 0; i-- {
		r := regs[i]
		if r >= 8 {
			code = append(code, 0x41)
		}
		code = append(code, 0x58+byte(r&7))
	}
	code = append(code, 0x9d, 0xc3)
	if indirect {
		for len(code)%8 != 0 {
			code = append(code, 0xcc)
		}
		binary.LittleEndian.PutUint32(code[call+2:], uint32(len(code)-(call+6)))
		code = append(code, make([]byte, 8)...)
	}
	return code, call
}

func arm64TLSThunk(reg int, helper, back uint32) section {
	code, call, jump := arm64TLSThunkCode(reg, false)
	return section{name: ".text", flags: pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ | 0x500000, size: uint32(len(code)), data: code, relocs: []pe.Reloc{{VirtualAddress: uint32(call), SymbolTableIndex: helper, Type: 3}, {VirtualAddress: uint32(jump), SymbolTableIndex: back, Type: 3}}}
}

// arm64TLSThunkCode returns the thunk, its helper call and its return branch.
// An indirect thunk loads the helper from an 8-byte literal after the branch
// into x16, which the thunk saves and restores with x0-x17.
func arm64TLSThunkCode(reg int, indirect bool) ([]byte, int, int) {
	var code []byte
	emit := func(v uint32) { code = binary.LittleEndian.AppendUint32(code, v) }
	emit(0xd10003ff | 544<<10) // SUB SP, SP, #544
	for r := uint32(0); r < 18; r += 2 {
		emit(0xa90003e0 | ((r/2)*2)<<15 | (r+1)<<10 | r)
	}
	emit(0xf90003fe | 18<<10) // STR LR, [SP,#144]
	emit(0xd53b4210)
	emit(0xf90003f0 | 19<<10) // save NZCV
	var vectors []uint32
	for r := uint32(0); r < 8; r++ {
		vectors = append(vectors, r)
	}
	for r := uint32(16); r < 32; r++ {
		vectors = append(vectors, r)
	}
	for i := 0; i < len(vectors); i += 2 {
		emit(0xad0003e0 | uint32(10+i)<<15 | vectors[i+1]<<10 | vectors[i])
	}
	call := len(code)
	if indirect {
		emit(0x58000010) // LDR X16, slot
		emit(0xd63f0200) // BLR X16
	} else {
		emit(0x94000000)
	}
	emit(0xf90003e0 | uint32(reg)<<10) // replace saved destination with helper result
	for i := 0; i < len(vectors); i += 2 {
		emit(0xad4003e0 | uint32(10+i)<<15 | vectors[i+1]<<10 | vectors[i])
	}
	emit(0xf94003f0 | 19<<10)
	emit(0xd51b4210)
	emit(0xf94003fe | 18<<10)
	for r := uint32(0); r < 18; r += 2 {
		emit(0xa94003e0 | ((r/2)*2)<<15 | (r+1)<<10 | r)
	}
	emit(0x910003ff | 544<<10)
	jump := len(code)
	emit(0x14000000)
	if indirect {
		if len(code)%8 != 0 {
			emit(0xd4200000) // BRK #0
		}
		literal := binary.LittleEndian.Uint32(code[call:]) | uint32((len(code)-call)/4)<<5
		binary.LittleEndian.PutUint32(code[call:], literal)
		code = append(code, make([]byte, 8)...)
	}
	return code, call, jump
}
