package main

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"path/filepath"
)

func auditAlignment(pkg, executable, module string, want128 bool) []map[string]any {
	symbols := map[string]uint64{}
	if f, err := elf.Open(executable); err == nil {
		defer f.Close()
		syms, err := f.Symbols()
		require(err)
		for _, s := range syms {
			symbols[s.Name] = s.Value
		}
		for _, p := range f.Progs {
			check(p.Type != elf.PT_LOAD || p.Flags&(elf.PF_W|elf.PF_X) != (elf.PF_W|elf.PF_X), "writable executable ELF load segment")
		}
	} else {
		f, err := macho.Open(executable)
		require(err)
		defer f.Close()
		check(f.Symtab != nil, "missing final Mach-O symbols")
		for _, s := range f.Symtab.Syms {
			symbols[s.Name] = s.Value
		}
	}
	var checked []map[string]any
	aligned128 := false
	artifacts, err := filepath.Glob(filepath.Join(pkg, "*.syso"))
	require(err)
	for _, artifact := range artifacts {
		f, err := elf.Open(artifact)
		require(err)
		for _, s := range f.Sections {
			if (s.Type != elf.SHT_PROGBITS && s.Type != elf.SHT_NOBITS) || s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 {
				continue
			}
			name := fmt.Sprintf("%s/native(%s)", module, s.Name)
			address, found := symbols[name]
			if !found {
				address, found = symbols["_"+name]
			}
			if !found {
				continue
			}
			check(s.Addralign != 0 && address%s.Addralign == 0, "section %s address %#x violates alignment %d", name, address, s.Addralign)
			checked = append(checked, map[string]any{"section": s.Name, "address": fmt.Sprintf("%#x", address), "alignment": s.Addralign})
			aligned128 = aligned128 || s.Addralign == 128
		}
		require(f.Close())
	}
	check(len(checked) >= 8, "not enough final native section addresses observed: %d", len(checked))
	check(!want128 || aligned128, "128-byte native alignment was not retained")
	return checked
}
