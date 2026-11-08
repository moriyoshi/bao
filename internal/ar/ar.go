// Package ar selects object members for Bao from the public archive parser.
// Archive symbol and name tables are bookkeeping, not native object inputs.
package ar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	archive "github.com/moriyoshi/bao/ar"
)

type Member = archive.Member

func Parse(b []byte) ([]Member, error) {
	members, err := archive.Parse(b)
	if err != nil {
		return nil, err
	}
	out := members[:0]
	for _, m := range members {
		if m.Kind == archive.Regular {
			out = append(out, m)
		}
	}
	return out, nil
}

// ParseCOFF selects the ordinary native plane of an EC-aware COFF archive.
// Such libraries can contain native objects and alternate ARM64EC/ARM64X ABI
// objects. Their explicit EC symbol map separates those planes. Bao supports
// only the ordinary AMD64/ARM64 plane; it never links the alternate ABI code.
// Generic Parse retains all ordinary members, including alternate ABI objects.
func ParseCOFF(b []byte) ([]Member, error) {
	return ParseCOFFForMachine(b, 0)
}

// ParseCOFFForMachine additionally selects the requested native architecture
// from explicitly EC-indexed hybrid libraries. Ordinary mixed archives remain
// unchanged so their caller can reject a target mismatch.
func ParseCOFFForMachine(b []byte, expected uint16) ([]Member, error) {
	members, err := archive.Parse(b)
	if err != nil {
		return nil, err
	}
	ecAware := false
	for _, m := range members {
		if m.Kind == archive.SymbolTable && m.Name == "/<ECSYMBOLS>/" {
			ecAware = true
		}
	}
	out := members[:0]
	importMachines := map[uint16]bool{}
	nativeMachines := map[uint16]bool{}
	for _, m := range members {
		if m.Kind != archive.Regular {
			continue
		}
		if ecAware && len(m.Data) >= 8 {
			machine := binary.LittleEndian.Uint16(m.Data)
			if machine == 0 && binary.LittleEndian.Uint16(m.Data[2:]) == 0xffff {
				machine = binary.LittleEndian.Uint16(m.Data[6:])
			}
			if machine == 0xa641 || machine == 0xa64e {
				continue
			}
			if expected != 0 && (machine == 0x8664 || machine == 0xaa64) && machine != expected {
				continue
			}
		}
		// CRT import libraries can also contain real static compatibility
		// wrappers. Retain those wrappers, but never infer DLL bindings from
		// their short import declarations. A declaration-only archive thus
		// contains no linkable native definitions for this view.
		machine := uint16(0)
		if len(m.Data) >= 20 {
			machine = binary.LittleEndian.Uint16(m.Data)
			if machine == 0 && binary.LittleEndian.Uint16(m.Data[2:]) == 0xffff {
				machine = binary.LittleEndian.Uint16(m.Data[6:])
			}
		}
		if (machine == 0x8664 || machine == 0xaa64) && (expected == 0 || machine == expected) && (shortCOFFImport(m.Data, machine) || coffImportSections(m.Data, machine)) {
			importMachines[machine] = true
			continue
		}
		if machine == 0x8664 || machine == 0xaa64 {
			nativeMachines[machine] = true
		}
		out = append(out, m)
	}
	for imported := range importMachines {
		for native := range nativeMachines {
			if expected == 0 && imported != native {
				return nil, fmt.Errorf("COFF archive import machine %#x differs from native machine %#x", imported, native)
			}
		}
	}
	return out, nil
}

func coffImportSections(data []byte, expected uint16) bool {
	if len(data) < 20 || binary.LittleEndian.Uint16(data) != expected || binary.LittleEndian.Uint16(data[16:]) != 0 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(data[2:]))
	if count > (len(data)-20)/40 {
		return false
	}
	for i := 0; i < count; i++ {
		name := data[20+40*i : 28+40*i]
		if bytes.Equal(name[:6], []byte(".idata")) && (name[6] == 0 || name[6] == '$') {
			return true
		}
	}
	return false
}

func shortCOFFImport(data []byte, expected uint16) bool {
	if len(data) < 20 || binary.LittleEndian.Uint16(data) != 0 || binary.LittleEndian.Uint16(data[2:]) != 0xffff || binary.LittleEndian.Uint16(data[4:]) > 1 || binary.LittleEndian.Uint16(data[6:]) != expected {
		return false
	}
	size := uint64(binary.LittleEndian.Uint32(data[12:]))
	kind := binary.LittleEndian.Uint16(data[18:])
	if size == 0 || size > uint64(len(data)-20) || kind&3 > 2 || (kind>>2)&7 > 4 {
		return false
	}
	parts := bytes.SplitN(data[20:20+size], []byte{0}, 3)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}
