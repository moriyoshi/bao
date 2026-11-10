package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moriyoshi/bao/bindings"
	"github.com/moriyoshi/bao/linuxelf"
	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/translate"
)

func (o *nativeFlags) resolveBindings(name string, input []byte) error {
	if o.bindings == "" && o.inlineBindings == nil {
		return nil
	}
	if o.signatures != nil {
		return nil
	}
	var m bindings.Manifest
	var err error
	if o.inlineBindings != nil {
		m, err = bindings.Parse(bytes.NewReader(o.inlineBindings))
	} else if o.bindings == "dwarf" {
		if len(o.symbols) == 0 {
			return usage("-bindings dwarf requires selected C ABI exports with -symbol")
		}
		m, err = bindings.Infer(name, input, o.symbols)
	} else {
		f, e := os.Open(o.bindings)
		if e != nil {
			return e
		}
		defer f.Close()
		m, err = bindings.Parse(f)
	}
	if err != nil {
		return fmt.Errorf("function signatures: %w", err)
	}
	if err = m.Validate(); err != nil {
		return err
	}
	for _, f := range m.Functions {
		exists := false
		for _, s := range o.symbols {
			exists = exists || s == f.Symbol
		}
		if !exists {
			o.symbols = append(o.symbols, f.Symbol)
		}
	}
	o.signatures = &m
	return nil
}

func generateWithBindings(o nativeFlags, target toolchain.Target, input, output string, stdout, stderr io.Writer) error {
	if strings.HasPrefix(target.Name, "windows/") {
		return generateWindows(o, target, input, output, stdout, stderr)
	}
	original, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	translated := original
	removed, bitcodeSections := 0, 0
	bitcodeBytes := uint64(0)
	darwin := strings.HasPrefix(target.Name, "darwin/")
	if o.stripBitcode {
		if darwin {
			translated, bitcodeSections, bitcodeBytes, err = translate.StripBitcode(translated)
		} else {
			translated, bitcodeSections, bitcodeBytes, err = linuxelf.StripBitcode(translated)
		}
		if err != nil {
			return fmt.Errorf("strip embedded LLVM bitcode: %w", err)
		}
		if bitcodeSections != 0 {
			fmt.Fprintf(stderr, "Dropped %d bytes of embedded LLVM bitcode from %d sections\n", bitcodeBytes, bitcodeSections)
		}
	}
	if o.stripDebug {
		if darwin {
			translated, removed, err = translate.StripDebug(translated)
		} else {
			translated, removed, err = linuxelf.StripDebug(translated)
		}
		if err != nil {
			return fmt.Errorf("strip native debug information: %w", err)
		}
	}
	if o.stripDebug || bitcodeSections != 0 {
		work, err := os.MkdirTemp(filepath.Dir(output), ".bao-strip-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		input = filepath.Join(work, "stripped.o")
		if err = os.WriteFile(input, translated, 0400); err != nil {
			return err
		}
	}
	if err = generateNativeRaw(o, target, input, output, stdout, stderr); err != nil {
		return err
	}
	if o.signatures != nil {
		if err = bindings.Generate(output, o.pkg, target.Name, *o.signatures, o.symbols); err != nil {
			return err
		}
	}
	debug := struct {
		Stripped        bool   `json:"stripped"`
		Sections        int    `json:"removed_sections"`
		Symbols         int    `json:"removed_symbols"`
		BitcodeStripped bool   `json:"bitcode_stripped"`
		BitcodeSections int    `json:"removed_bitcode_sections"`
		BitcodeBytes    uint64 `json:"removed_bitcode_bytes"`
		Original        string `json:"original_sha256"`
		Translated      string `json:"stripped_sha256"`
		Unwind          bool   `json:"runtime_unwind_preserved"`
	}{o.stripDebug, removed, max(0, nativeSymbolCount(original)-nativeSymbolCount(translated)), o.stripBitcode, bitcodeSections, bitcodeBytes, fmt.Sprintf("%x", sha256.Sum256(original)), fmt.Sprintf("%x", sha256.Sum256(translated)), true}
	b, err := json.MarshalIndent(debug, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(output, "bao-debug.json"), append(b, '\n'))
}

func nativeSymbolCount(b []byte) int {
	if bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			return 0
		}
		defer f.Close()
		s, _ := f.Symbols()
		return len(s)
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		return 0
	}
	defer f.Close()
	if f.Symtab == nil {
		return 0
	}
	return len(f.Symtab.Syms)
}

func inferBindings(args []string, stdout io.Writer) error {
	fs := newFlags("bindings", "bindings -symbol C_EXPORT [-symbol C_EXPORT] [-o signatures.json] INPUT", "Infer a scalar C ABI signature manifest from full DWARF in optimized native code. Selected exports assert the C ABI; inference does not authenticate code.")
	var symbols symbolFlags
	fs.Var(&symbols, "symbol", "C ABI native export to infer; repeatable")
	out := fs.String("o", "", "new JSON file; default stdout")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 1 || len(symbols) == 0 {
		return usage("bindings requires one native object/archive and selected -symbol exports")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := bindings.Infer(fs.Arg(0), b, symbols)
	if err != nil {
		return err
	}
	if *out == "" {
		return writeJSON(stdout, m)
	}
	b, err = json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(*out, append(b, '\n'))
}
