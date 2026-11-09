package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/moriyoshi/bao/bindings"
	"github.com/moriyoshi/bao/toolchain"
)

type nativeFlags struct {
	target, output, pkg, sdk, sysroot string
	symbols                           symbolFlags
	asJSON                            bool
	bindings                          string
	signatures                        *bindings.Manifest
	stripDebug                        bool
	windowsImports                    symbolFlags
	windowsImportLibraries            symbolFlags
	windowsMaxDataAlignment           uint
	linuxSystemLibraries              symbolFlags
	config                            string
	inlineBindings                    []byte
	diagnostics                       diagnosticFlags
	diagnosticCommand                 string
	diagnosticSource                  string
	windowsCXXRuntime                 string
	windowsCRT                        string
}

func (o *nativeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.config, "config", "", "JSON file supplying these options, including bindings; defaults to .bao.config.json in the working directory if it exists, and empty disables that; a flag given on the command line replaces its setting")
	fs.StringVar(&o.target, "target", "auto", "GOOS/GOARCH; auto detects native inputs, uses host for Cargo")
	fs.StringVar(&o.output, "o", "", "new generated Go package directory (required)")
	fs.StringVar(&o.pkg, "package", "native", "generated Go package name")
	fs.StringVar(&o.sdk, "sdk", "", "macOS SDK path; auto-discovered with xcrun on macOS")
	fs.StringVar(&o.sysroot, "sysroot", "", "target Linux glibc sysroot; defaults to / on a matching native Linux host")
	fs.Var(&o.symbols, "symbol", "native C ABI export without Mach-O's extra underscore; repeatable, accessor order is preserved")
	fs.Var(&o.windowsImports, "windows-import", "explicit Windows system import SYMBOL=DLL.dll; repeatable")
	fs.Var(&o.windowsImportLibraries, "windows-import-library", "short-import library naming system DLL functions, such as libuser32.a; repeatable, first match wins, never overrides -windows-import or built-in bindings")
	fs.UintVar(&o.windowsMaxDataAlignment, "windows-max-data-alignment", 0, "link read-only data requesting more alignment at this value; only 32 is supported, and capped sections are recorded in the manifest")
	fs.Var(&o.linuxSystemLibraries, "linux-system-library", "additional target shared object in -sysroot, such as libxcb.so.1; repeatable")
	fs.StringVar(&o.windowsCXXRuntime, "windows-cxx-runtime", "auto", "Windows C++ runtime: auto (MSVC/libstdc++), libstdc++, or libc++ (LLVM-MinGW)")
	fs.StringVar(&o.windowsCRT, "windows-crt", "ucrt", "Windows system C runtime: ucrt or msvcrt; match the producer toolchain")
	o.diagnostics.register(fs)
	fs.BoolVar(&o.asJSON, "json", false, "print the generated package result as JSON")
	fs.StringVar(&o.bindings, "bindings", "", "signature manifest JSON, or dwarf to infer selected C ABI exports; omission uses purego")
	fs.BoolVar(&o.stripDebug, "strip-debug", true, "strip native debug data after inference; preserve unwind/exception metadata and original input")
}

func (o *nativeFlags) validate() error {
	if o.target != "auto" {
		if _, err := toolchain.ParseTarget(o.target); err != nil {
			return usage("%v", err)
		}
	}
	if o.output == "" {
		return usage("-o new-directory is required")
	}
	if !token.IsIdentifier(o.pkg) || o.pkg == "_" {
		return usage("invalid package name %q", o.pkg)
	}
	for _, name := range o.symbols {
		if !token.IsIdentifier(name) || name == "_" {
			return usage("invalid export name %q", name)
		}
	}
	if o.bindings == "dwarf" && len(o.symbols) == 0 {
		return usage("-bindings dwarf requires selected C ABI exports with -symbol")
	}
	if o.bindings != "" && o.bindings != "dwarf" || o.inlineBindings != nil {
		return o.resolveBindings("", nil)
	}
	return nil
}

func resolveTarget(requested, input string) (toolchain.Target, bool, error) {
	if input == "" {
		if requested == "auto" {
			t, err := toolchain.HostTarget()
			return t, false, err
		}
		t, err := toolchain.ParseTarget(requested)
		return t, false, err
	}
	t, archive, err := toolchain.Detect(input)
	if err != nil {
		return t, archive, err
	}
	if requested != "auto" && requested != t.Name {
		return t, archive, fmt.Errorf("input target is %s, not requested %s", t.Name, requested)
	}
	return t, archive, nil
}

func resolvePlatform(ctx context.Context, o *nativeFlags, target toolchain.Target, run toolchain.RunFunc) error {
	if o.windowsMaxDataAlignment != 0 && o.windowsMaxDataAlignment != 32 {
		return usage("-windows-max-data-alignment supports only 32")
	}
	if len(o.linuxSystemLibraries) > 0 && !strings.HasPrefix(target.Name, "linux/") {
		return usage("-linux-system-library requires a Linux target")
	}
	if strings.HasPrefix(target.Name, "windows/") {
		if o.sdk != "" || o.sysroot != "" {
			return usage("Windows COFF uses system DLL imports; -sdk/-sysroot do not apply")
		}
		return nil
	}
	if len(o.windowsImports) > 0 || len(o.windowsImportLibraries) > 0 || o.windowsMaxDataAlignment != 0 || o.windowsCXXRuntime != "auto" && o.windowsCXXRuntime != "" || o.windowsCRT != "" && o.windowsCRT != "ucrt" {
		return usage("-windows-import/-windows-import-library/-windows-max-data-alignment/-windows-cxx-runtime/-windows-crt requires a Windows target")
	}
	if strings.HasPrefix(target.Name, "darwin/") {
		if o.sysroot != "" {
			return usage("-sysroot is for Linux; use -sdk for darwin/arm64")
		}
		if o.sdk == "" {
			if runtime.GOOS != "darwin" {
				return usage("cross translation to darwin/arm64 requires -sdk")
			}
			b, err := run(ctx, toolchain.Command{Tool: "xcrun", Args: []string{"--show-sdk-path"}})
			if err != nil {
				return err
			}
			o.sdk = trimOutput(b)
		}
		if o.sdk == "" {
			return fmt.Errorf("macOS SDK discovery returned an empty path")
		}
		var err error
		o.sdk, err = filepath.Abs(o.sdk)
		return err
	}
	if o.sdk != "" {
		return usage("-sdk is for macOS; use -sysroot for linux/arm64")
	}
	if o.sysroot == "" {
		if target.Name != runtime.GOOS+"/"+runtime.GOARCH {
			return usage("cross translation to %s requires -sysroot with target glibc/libgcc libraries", target.Name)
		}
		o.sysroot = "/"
	}
	var err error
	o.sysroot, err = filepath.Abs(o.sysroot)
	return err
}

func generateNative(o nativeFlags, target toolchain.Target, input, output string, stdout, stderr io.Writer) error {
	d := o.diagnostics.begin(o.diagnosticCommand, target, input, o.diagnosticSource, stderr)
	if d != nil {
		d.sysroot = o.sysroot
	}
	err := generateWithBindings(o, target, input, output, stdout, stderr)
	return d.finish(err, output)
}

func generateNativeRaw(o nativeFlags, target toolchain.Target, input, output string, stdout, stderr io.Writer) error {
	args := []string{"-o", output, "-package", o.pkg}
	for _, name := range o.symbols {
		args = append(args, "-symbol", name)
	}
	if strings.HasPrefix(target.Name, "linux/") {
		for _, name := range o.linuxSystemLibraries {
			args = append(args, "-linux-system-library", name)
		}
		return translateELF(append(args, "-sysroot", o.sysroot, input), stderr)
	}
	return runLegacy(append([]string{"translate"}, append(args, "-sdk", o.sdk, input)...), stdout, stderr)
}

type packageResult struct {
	Target   string   `json:"target"`
	Output   string   `json:"output"`
	Manifest string   `json:"manifest"`
	Symbols  []string `json:"symbols"`
	Bindings string   `json:"bindings"`
}

func showPackage(o nativeFlags, target toolchain.Target, stdout io.Writer) error {
	mode := "purego"
	if o.signatures != nil {
		mode = "generated"
	}
	r := packageResult{target.Name, filepath.Clean(o.output), filepath.Join(o.output, "bao-manifest.json"), append([]string{}, o.symbols...), mode}
	if o.asJSON {
		return writeJSON(stdout, r)
	}
	fmt.Fprintf(stdout, "Generated %s for %s\n", r.Output, r.Target)
	if o.signatures != nil {
		fmt.Fprintln(stdout, "Consumer: CGO_ENABLED=0 go build (generated typed bindings; no purego module required)")
		fmt.Fprintln(stdout, "Cgo-enabled consumer: CGO_ENABLED=1 go build -ldflags=-linkmode=internal (see README for verified targets)")
	} else {
		fmt.Fprintln(stdout, "Consumer: CGO_ENABLED=0 go build (requires purego)")
	}
	return nil
}

func translateNative(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("translate", "translate [options] combined.o", "Translate an already-combined native object into a Go package. No native compiler/linker is invoked.")
	o := nativeFlags{diagnosticCommand: "translate"}
	o.register(fs)
	format := fs.String("format", "elf", "linker input container; only elf preserves native alignment")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	positional, err := o.applyConfig(fs, stderr)
	if err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	if len(positional) != 1 || *format != "elf" {
		return usage("translate requires one combined object and -format elf; use build for archives, probe-tls for Mach-O diagnostics")
	}
	if err := requireNewOutput(o.output); err != nil {
		return err
	}
	target, archive, err := resolveTarget(o.target, positional[0])
	if err != nil {
		return err
	}
	if archive && !strings.HasPrefix(target.Name, "windows/") {
		return usage("translate requires a combined object; use 'bao build' to combine an archive")
	}
	executor := &toolchain.Executor{Stderr: stderr}
	if err := resolvePlatform(ctx, &o, target, executor.Run); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	inputBytes, err := os.ReadFile(positional[0])
	if err != nil {
		return err
	}
	if err = o.resolveBindings(positional[0], inputBytes); err != nil {
		return err
	}
	work, err := os.MkdirTemp(filepath.Dir(o.output), ".bao-translate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	staged := filepath.Join(work, "package")
	if err := generateNative(o, target, positional[0], staged, stdout, stderr); err != nil {
		return err
	}
	if err = toolchain.Publish(staged, o.output); err != nil {
		return err
	}
	return showPackage(o, target, stdout)
}

func requireNewOutput(output string) error {
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output %q already exists; choose a new directory", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent, err := os.Stat(filepath.Dir(output))
	if err != nil {
		return fmt.Errorf("output parent must exist: %w", err)
	}
	if !parent.IsDir() {
		return fmt.Errorf("output parent is not a directory")
	}
	return nil
}

func buildNative(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("build", "build [options] [library.a|combined.o|Cargo.toml|crate-directory]", "Build a native library into a Go package. Cargo and native ld run only on this producer machine.")
	var o nativeFlags
	o.register(fs)
	manifest := fs.String("manifest-path", "", "Cargo.toml to build; defaults to ./Cargo.toml when no input is given")
	cargoPackage := fs.String("cargo-package", "", "Cargo workspace package containing one staticlib target")
	offline := fs.Bool("offline", false, "pass --offline to Cargo")
	locked := fs.Bool("locked", false, "pass --locked to Cargo")
	linker := fs.String("ld", "", "native/cross linker executable; platform default when omitted")
	minOS := fs.String("min-os", "11.0", "macOS deployment version for archive partial linking")
	var linkArchives, linkNotices symbolFlags
	fs.Var(&linkArchives, "link-archive", "additional static dependency archive; repeatable, searched for unresolved native references")
	fs.Var(&linkNotices, "link-notice", "license/notice file for linked native dependencies; repeatable, retained in the generated package")
	requireStaticRuntime := fs.Bool("require-static-runtime", false, "reject generated imports of standard shared C++/Rust/unwind runtimes; OS libraries remain permitted")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	positional, err := o.applyConfig(fs, stderr)
	if err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	if len(positional) > 1 || (len(positional) == 1 && *manifest != "") {
		return usage("build accepts one input or -manifest-path, not both")
	}
	input := ""
	if len(positional) == 1 {
		input = positional[0]
		if stat, err := os.Stat(input); err == nil && stat.IsDir() {
			*manifest, input = filepath.Join(input, "Cargo.toml"), ""
		} else if filepath.Base(input) == "Cargo.toml" {
			*manifest, input = input, ""
		}
	} else if *manifest == "" {
		*manifest = "Cargo.toml"
	}
	if *manifest == "" && (*cargoPackage != "" || *offline || *locked) {
		return usage("Cargo options require a Cargo manifest or crate directory")
	}
	if err := requireNewOutput(o.output); err != nil {
		return err
	}
	target, archive, err := resolveTarget(o.target, input)
	if err != nil {
		return err
	}
	if strings.HasPrefix(target.Name, "windows/") && *linker != "" {
		return usage("Windows COFF archive selection is built in; -ld is unsupported")
	}
	executor := &toolchain.Executor{Stderr: stderr}
	if err := resolvePlatform(ctx, &o, target, executor.Run); err != nil {
		return err
	}
	// Work beside the destination so final publication is a same-filesystem
	// rename. Cleanup only ever removes this invocation's private directory.
	work, err := os.MkdirTemp(filepath.Dir(o.output), ".bao-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if *manifest != "" {
		fmt.Fprintf(stderr, "Building Rust staticlib for %s\n", target.RustTriple)
		input, err = toolchain.CargoArchive(ctx, executor.Run, toolchain.CargoOptions{
			Manifest: *manifest, Package: *cargoPackage, Target: target, Offline: *offline, Locked: *locked, Debug: o.bindings == "dwarf",
		}, stderr)
		if err != nil {
			return err
		}
		if _, archive, err = resolveTarget(target.Name, input); err != nil {
			return err
		}
		if !archive {
			return fmt.Errorf("Cargo staticlib artifact is not an ordinary archive")
		}
	}
	inputBytes, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	sourceHash := fmt.Sprintf("%x", sha256.Sum256(inputBytes))
	type linkedInput struct {
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
		Artifact string `json:"artifact,omitempty"`
	}
	// Link immutable private copies, and record the bytes that those copies
	// contain. Changes to caller-owned files during a producer invocation cannot
	// change native inputs after their provenance digests have been recorded.
	nativeInput := filepath.Join(work, "primary.o")
	if archive {
		nativeInput = filepath.Join(work, "primary.a")
	}
	if err := writeNew(nativeInput, inputBytes); err != nil {
		return err
	}
	linked := []linkedInput{}
	dependencies := []string{}
	for i, path := range linkArchives {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot := filepath.Join(work, fmt.Sprintf("dependency-%d.a", i))
		if err := writeNew(snapshot, data); err != nil {
			return err
		}
		dependencies = append(dependencies, snapshot)
		linked = append(linked, linkedInput{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))})
	}
	notices := []linkedInput{}
	noticeBytes := [][]byte{}
	for i, path := range linkNotices {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("bao-linked-license-%d.txt", i)
		notices = append(notices, linkedInput{path, fmt.Sprintf("%x", sha256.Sum256(data)), name})
		noticeBytes = append(noticeBytes, data)
	}
	if err = o.resolveBindings(input, inputBytes); err != nil {
		return err
	}
	combined := nativeInput
	if archive && !strings.HasPrefix(target.Name, "windows/") || len(linkArchives) > 0 {
		fmt.Fprintf(stderr, "Combining archive for %s\n", target.Name)
		combined = filepath.Join(work, "combined.o")
		if err := toolchain.CombineWithArchives(ctx, executor.Run, target, *linker, o.sdk, *minOS, nativeInput, combined, dependencies); err != nil {
			return err
		}
	}
	// Check linker output as well: an accidental host linker cannot silently
	// switch the requested target or leave an archive as a purported object.
	if _, stillArchive, err := resolveTarget(target.Name, combined); err != nil {
		return err
	} else if stillArchive && !strings.HasPrefix(target.Name, "windows/") {
		return fmt.Errorf("native linker did not produce a combined object")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	staged := filepath.Join(work, "package")
	o.diagnosticSource = nativeInput
	if err := generateNative(o, target, combined, staged, stdout, stderr); err != nil {
		return err
	}
	if *requireStaticRuntime {
		if err := verifyStaticRuntimeImports(staged); err != nil {
			return err
		}
	}
	for i, notice := range notices {
		if err := writeNew(filepath.Join(staged, notice.Artifact), noticeBytes[i]); err != nil {
			return err
		}
	}
	bytes, err := os.ReadFile(combined)
	if err != nil {
		return err
	}
	provenance := struct {
		Schema               int                 `json:"schema_version"`
		Bao                  string              `json:"bao_version"`
		Target               toolchain.Target    `json:"target"`
		Source               string              `json:"source"`
		SourceSHA256         string              `json:"source_sha256"`
		CombinedSHA256       string              `json:"combined_sha256"`
		CargoManifest        string              `json:"cargo_manifest,omitempty"`
		Symbols              []string            `json:"symbols"`
		Commands             []toolchain.Command `json:"producer_commands"`
		LinkedArchives       []linkedInput       `json:"linked_archives,omitempty"`
		LinkedNotices        []linkedInput       `json:"linked_notices,omitempty"`
		RequireStaticRuntime bool                `json:"require_static_runtime,omitempty"`
	}{1, version, target, input, sourceHash, fmt.Sprintf("%x", sha256.Sum256(bytes)), *manifest, append([]string{}, o.symbols...), executor.Commands, linked, notices, *requireStaticRuntime}
	b, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(staged, "bao-build.json"), append(b, '\n')); err != nil {
		return err
	}
	if err := requireNewOutput(o.output); err != nil {
		return err
	}
	if err := toolchain.Publish(staged, o.output); err != nil {
		return err
	}
	return showPackage(o, target, stdout)
}
