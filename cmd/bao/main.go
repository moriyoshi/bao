// bao translates native objects into packages for Go's internal linker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/moriyoshi/bao/translate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bao:", err)
		os.Exit(exitCode(err))
	}
}

func runLegacy(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: bao inspect|pack|translate|translate-elf|probe-lower-tlvp|probe-tls [options] file.a|file.o")
	}
	cmd := args[0]
	if cmd == "translate-elf" {
		return translateELF(args[1:], stderr)
	}
	if cmd != "inspect" && cmd != "pack" && cmd != "translate" && cmd != "probe-lower-tlvp" && cmd != "probe-tls" {
		return fmt.Errorf("unknown command %q", cmd)
	}
	fs := newFlags(cmd, cmd+" [options] INPUT", "Low-level "+cmd+" command; use build or translate for the primary producer workflow.")
	out, pkg, sdk, container := new(string), new(string), new(string), new(string)
	*pkg = "native"
	metadata := new(bool)
	var symbols symbolFlags
	if cmd != "inspect" {
		fs.StringVar(out, "o", "", "new output directory, or intermediate .o file for probe-lower-tlvp (required)")
	}
	if cmd == "pack" || cmd == "translate" || cmd == "probe-tls" {
		fs.StringVar(pkg, "package", "native", "generated Go package name")
		fs.Var(&symbols, "symbol", "native export without Mach-O's extra leading underscore; repeatable")
	}
	if cmd == "translate" || cmd == "probe-tls" {
		fs.StringVar(sdk, "sdk", "", "macOS SDK for system import bindings")
		fs.BoolVar(metadata, "runtime", false, "register native unwind records and run initializers (requires -sdk)")
		fs.StringVar(container, "format", "", "elf (translate default) or diagnostic macho (probe-tls default)")
	}
	if err := parseFlags(fs, args[1:], stdout); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usage("exactly one input object or ordinary archive is required")
	}
	input, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if cmd == "translate" && translate.IsDylib(input) {
		dylib, anchor, err := translate.PrepareDylib(input, symbols)
		if err != nil {
			return err
		}
		if *out == "" {
			return usage("-o is required")
		}
		report, err := translate.Inspect(anchor.Data, []translate.Object{anchor})
		if err != nil {
			return err
		}
		return probeDylib(*out, *pkg, *sdk, symbols, dylib, anchor, report, stderr)
	}
	objects, err := translate.Parse(filepath.Base(fs.Arg(0)), input)
	if err != nil {
		return err
	}
	report, err := translate.Inspect(input, objects)
	if err != nil {
		return err
	}
	encode := func(v any) error {
		e := json.NewEncoder(stdout)
		e.SetIndent("", "  ")
		return e.Encode(v)
	}
	if cmd == "inspect" {
		return encode(report)
	}
	if *out == "" {
		return usage("-o is required")
	}
	if cmd == "probe-tls" || cmd == "translate" {
		if *container == "" {
			if cmd == "translate" {
				*container = "elf"
			} else {
				*container = "macho"
			}
		}
		if cmd == "translate" && *container != "elf" {
			return errors.New("translate requires the ELF input container to preserve native alignment; probe-tls provides the Mach-O diagnostic")
		}
		return probeTLS(*out, *pkg, *sdk, *container, *metadata || cmd == "translate", symbols, input, objects, report, stderr)
	}
	if cmd == "probe-lower-tlvp" {
		if len(objects) != 1 || filepath.Ext(*out) != ".o" {
			return errors.New("probe requires one Mach-O object and an intermediate .o output, not a .syso or archive")
		}
		lowered, count, err := translate.LowerTLVP(objects[0])
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("no TLVP relocations to lower")
		}
		post, err := translate.Inspect(lowered, []translate.Object{{Name: filepath.Base(*out), Data: lowered}})
		if err != nil {
			return err
		}
		evidence := struct {
			Status string           `json:"status"`
			Count  int              `json:"tlvp_relocations_lowered"`
			Before translate.Report `json:"before"`
			After  translate.Report `json:"after"`
		}{"INCOMPLETE: relocation experiment only; TLS, imports, constructors and unwind lifecycle remain unsupported", count, report, post}
		b, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*out, lowered); err != nil {
			return err
		}
		if err := writeNew(*out+".json", append(b, '\n')); err != nil {
			os.Remove(*out) // Only the file exclusively created above.
			return err
		}
		fmt.Fprintf(stderr, "INCOMPLETE intermediate: lowered %d TLVP relocations; see %s.json\n", count, *out)
		return nil
	}
	if !report.Packable {
		if err := encode(report); err != nil {
			return err
		}
		return errors.New("unsupported input; no output directory created (inspect blockers above)")
	}
	if !token.IsIdentifier(*pkg) || *pkg == "_" {
		return usage("invalid package name %q", *pkg)
	}
	// Assembly identifiers are deliberately restricted. Do not interpolate raw
	// Mach-O names into generated Go assembler source.
	for _, s := range symbols {
		if !token.IsIdentifier(s) || s == "_" {
			return usage("unsupported assembly symbol name %q", s)
		}
		found := false
		for _, o := range objects {
			ok, err := translate.HasExport(o, "_"+s)
			if err != nil {
				return err
			}
			found = found || ok
		}
		if !found {
			return fmt.Errorf("requested symbol %q is not an external definition", s)
		}
	}
	if err := os.Mkdir(*out, 0o755); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(*out) // This invocation exclusively created the directory.
		}
	}()
	for i, o := range objects {
		name := fmt.Sprintf("native_%06d_darwin_arm64.syso", i)
		if err := writeNew(filepath.Join(*out, name), o.Data); err != nil {
			return err
		}
	}
	var goSource, asm strings.Builder
	fmt.Fprintf(&goSource, "// Code generated by bao; DO NOT EDIT.\n//go:build darwin && arm64\n\npackage %s\n", *pkg)
	asm.WriteString("// Code generated by bao; DO NOT EDIT.\n#include \"textflag.h\"\n")
	for i, s := range symbols {
		fmt.Fprintf(&goSource, "\n// SymbolAddr%d returns the native address of %s for an ABI-aware foreign call.\nfunc SymbolAddr%d() uintptr\n", i, s, i)
		fmt.Fprintf(&asm, "TEXT ·SymbolAddr%d(SB),NOSPLIT,$0-8\n\tMOVD $%s(SB), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n", i, s)
	}
	if err := writeNew(filepath.Join(*out, "symbols_darwin_arm64.go"), []byte(goSource.String())); err != nil {
		return err
	}
	if len(symbols) > 0 {
		if err := writeNew(filepath.Join(*out, "symbols_darwin_arm64.s"), []byte(asm.String())); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*out, "bao-manifest.json"), append(b, '\n')); err != nil {
		return err
	}
	complete = true
	fmt.Fprintf(stderr, "packaged %d objects; Go link and execution must be verified separately\n", len(objects))
	return nil
}

type symbolFlags []string

func (s *symbolFlags) String() string { return strings.Join(*s, ",") }
func (s *symbolFlags) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(path)
		return errors.Join(err, closeErr)
	}
	return nil
}
