package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
	"github.com/moriyoshi/bao/toolchain"
)

// inspectExecutable handles a built Mach-O program; other inputs fall through.
func inspectExecutable(flags diagnosticFlags, path, manifest string, out io.Writer) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil || f.Type != macho.TypeExec {
		return false, nil
	}
	defer f.Close()
	d := newDiagnosticSession(flags, "inspect", "darwin/executable", path, out)
	if err := d.checkExecutable(f, data, manifest); err != nil {
		return true, err
	}
	failures := d.failures()
	d.report.Result = fmt.Sprintf("finished: %d failures; execution not verified", failures)
	if d.printing() {
		fmt.Fprintln(out, d.report.Result)
	}
	d.close()
	if failures != 0 {
		return true, fmt.Errorf("executable bind check found %d failures", failures)
	}
	return true, nil
}

func inspectNative(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("inspect", "inspect INPUT", "Inspect a Darwin object/archive, Linux ELF object, or Windows COFF object/archive. Reports do not prove a successful translation or execution.")
	var diag diagnosticFlags
	diag.register(fs)
	manifest := fs.String("manifest", "", "bao-manifest.json to compare with a built executable's binds; requires -v")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usage("inspect requires one input object or archive")
	}
	if diag.enabled() {
		if handled, err := inspectExecutable(diag, fs.Arg(0), *manifest, stderr); handled {
			return err
		}
	}
	target, archive, err := toolchain.Detect(fs.Arg(0))
	if err != nil {
		return err
	}
	if d := diag.begin("inspect", target, fs.Arg(0), "", stderr); d != nil {
		d.skip("generate", "inspect does not translate")
		d.report.Result = "finished: input limits only; translation and execution not verified"
		if d.printing() {
			fmt.Fprintln(stderr, d.report.Result)
		}
		d.close()
	}
	if strings.HasPrefix(target.Name, "darwin/") {
		return runLegacy(append([]string{"inspect"}, args...), stdout, stderr)
	}
	if strings.HasPrefix(target.Name, "windows/") {
		input, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		members := []ar.Member{{Name: "input.obj", Data: input}}
		if archive {
			members, err = ar.Parse(input)
			if err != nil {
				return err
			}
		}
		type section struct {
			Name        string `json:"name"`
			Size        uint32 `json:"size"`
			Flags       uint32 `json:"flags"`
			Relocations int    `json:"relocations"`
		}
		type member struct {
			Name     string    `json:"name"`
			Symbols  int       `json:"symbols"`
			Sections []section `json:"sections"`
		}
		result := struct {
			Target  string   `json:"target"`
			Format  string   `json:"format"`
			Status  string   `json:"status"`
			Members []member `json:"members"`
		}{Target: target.Name, Format: "COFF", Status: "STRUCTURAL INSPECTION ONLY: translation and native execution remain separate checks"}
		for _, m := range members {
			f, err := pe.NewFile(bytes.NewReader(m.Data))
			if err != nil {
				return err
			}
			x := member{Name: m.Name, Symbols: len(f.Symbols)}
			for _, s := range f.Sections {
				x.Sections = append(x.Sections, section{s.Name, s.Size, s.Characteristics, len(s.Relocs)})
			}
			result.Members = append(result.Members, x)
			f.Close()
		}
		return writeJSON(stdout, result)
	}
	if archive {
		return usage("Linux ELF inspection requires a combined object; use 'bao build' for archives")
	}
	f, err := elf.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return err
	}
	type section struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Size      uint64 `json:"size"`
		Alignment uint64 `json:"alignment"`
		TLS       bool   `json:"tls"`
	}
	result := struct {
		Target   string    `json:"target"`
		Format   string    `json:"format"`
		Symbols  int       `json:"symbols"`
		Sections []section `json:"allocated_sections"`
		Status   string    `json:"status"`
	}{Target: target.Name, Format: "ELF64 ET_REL", Symbols: len(syms), Status: "STRUCTURAL INSPECTION ONLY: translate with a target sysroot, then verify link and execution"}
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC != 0 {
			result.Sections = append(result.Sections, section{s.Name, s.Type.String(), s.Size, s.Addralign, s.Flags&elf.SHF_TLS != 0})
		}
	}
	return writeJSON(stdout, result)
}
