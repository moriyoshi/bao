package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/verify"
)

// Set with -ldflags '-X main.version=... -X main.commit=...' for releases.
var version = "devel"
var commit string

type usageError struct{ error }

func usage(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

func exitCode(err error) int {
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var u usageError
	if errors.As(err, &u) {
		return 2
	}
	return 1
}

func parseFlags(fs *flag.FlagSet, args []string, stdout io.Writer) error {
	// flag's error path prints before returning. Keep diagnostics on stderr via
	// main, while successful help goes only to stdout.
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		fs.SetOutput(stdout)
		fs.Usage()
		return flag.ErrHelp
	}
	if err != nil {
		return usage("%s: %v", fs.Name(), err)
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) error {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := dispatch(ctx, args, stdout, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

const overview = `Bao builds native libraries into Go packages for CGO_ENABLED=0.

Usage:
  bao <command> [options]

Commands:
  build       Build a Cargo staticlib or combine an archive, then translate it
  translate   Translate one already-combined native object (auto-detect target)
  inspect     Inspect a raw Darwin object/archive or Linux ELF object
  bindings    Infer a function signature manifest from full native DWARF
  doctor      Check the producer toolchain for a target
  verify      Scan downloaded dependency sources without building
  verified-build  Authenticate signed native modules and build with private inputs/cache
  sign        Sign a complete generated module release (producer)
  keygen      Generate Ed25519 PEM keys (producer)
  targets     List supported targets and Rust triples
  version     Show Bao's build version and linker profile
  help        Show command help

Examples:
  bao build -manifest-path examples/core_graphics/Cargo.toml -symbol bao_example_run -o native
  bao build -target darwin/arm64 -symbol native_fn -o native libnative.a
  bao translate -target linux/arm64 -sysroot target-root -symbol native_fn -o native combined.o

Targets: darwin/arm64, darwin/amd64; linux/arm64, linux/amd64, linux/loong64, linux/ppc64le (glibc);
windows/amd64, windows/arm64 (COFF, CRT/TLS/C++; GNU Rust std with bundled unwinding).
One native runtime image per consumer. Run 'bao targets' for profiles.
Producer builds may invoke Cargo and a native linker. Consumers need Go;
purego is required only for runtime registration, not generated typed bindings.
Existing output directories are never overwritten. Use 'bao help <command>'.

Additional low-level commands: pack, translate-elf, probe-lower-tlvp, probe-tls.
`

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, err := io.WriteString(stdout, overview)
		return err
	}
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) == 1 {
			_, err := io.WriteString(stdout, overview)
			return err
		}
		if len(args) != 2 || strings.HasPrefix(args[1], "-") || args[1] == "help" {
			return usage("usage: bao help [command]")
		}
		return dispatch(ctx, []string{args[1], "-h"}, stdout, stderr)
	case "version", "-version", "--version":
		return showVersion(args[1:], stdout)
	case "targets":
		return showTargets(args[1:], stdout)
	case "doctor":
		return doctor(ctx, args[1:], stdout, stderr)
	case "build":
		return buildNative(ctx, args[1:], stdout, stderr)
	case "bindings":
		return inferBindings(args[1:], stdout)
	case "verify", "verified-build", "sign", "keygen":
		return signatureCommand(ctx, args[0], args[1:], stdout, stderr)
	case "_verified-tool":
		return verify.Tool(ctx, args[1:], stdout, stderr)
	case "translate":
		return translateNative(ctx, args[1:], stdout, stderr)
	case "translate-elf":
		// Keep the existing Linux spelling as an alias of the target-aware CLI.
		return translateNative(ctx, append([]string{"-target", "linux/arm64"}, args[1:]...), stdout, stderr)
	case "inspect":
		return inspectNative(args[1:], stdout, stderr)
	case "pack", "probe-lower-tlvp", "probe-tls":
		return runLegacy(args, stdout, stderr)
	default:
		return usage("unknown command %q; run 'bao help'", args[0])
	}
}

func newFlags(name, synopsis, description string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\n\nUsage: bao %s\n\nOptions:\n", description, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func writeJSON(w io.Writer, value any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func showVersion(args []string, stdout io.Writer) error {
	fs := newFlags("version", "version [-json]", "Show Bao's build and verified linker version.")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usage("version accepts no positional arguments")
	}
	revision := commit
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if revision == "" && setting.Key == "vcs.revision" {
				revision = setting.Value
			}
		}
	}
	info := struct {
		Version string `json:"version"`
		Commit  string `json:"commit,omitempty"`
		Go      string `json:"built_with"`
		Linker  string `json:"verified_go_linker"`
	}{version, revision, runtime.Version(), "go1.26.11"}
	if *asJSON {
		return writeJSON(stdout, info)
	}
	fmt.Fprintf(stdout, "bao %s", info.Version)
	if revision != "" {
		fmt.Fprintf(stdout, " (%s)", revision)
	}
	fmt.Fprintf(stdout, "\nbuilt with %s; verified consumer linker: %s\n", info.Go, info.Linker)
	return nil
}

func showTargets(args []string, stdout io.Writer) error {
	fs := newFlags("targets", "targets [-json]", "List the tested native target profiles.")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usage("targets accepts no positional arguments")
	}
	if *asJSON {
		return writeJSON(stdout, toolchain.Targets())
	}
	for _, target := range toolchain.Targets() {
		fmt.Fprintf(stdout, "%-14s %-30s %s\n", target.Name, target.RustTriple, target.Object)
	}
	return nil
}
