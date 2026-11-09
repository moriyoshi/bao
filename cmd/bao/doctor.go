package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/moriyoshi/bao/linuxelf"
	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/translate"
)

func trimOutput(b []byte) string { return strings.TrimSpace(string(b)) }

type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func doctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("doctor", "doctor [options]", "Check the full Rust/archive producer toolchain. Existing combined-object translation and consumers need fewer tools.")
	targetName := fs.String("target", "auto", "GOOS/GOARCH; default host")
	sdk := fs.String("sdk", "", "macOS SDK path; auto-discovered on macOS")
	sysroot := fs.String("sysroot", "", "target Linux glibc sysroot; / on a native Linux producer")
	linker := fs.String("ld", "", "native/cross linker executable")
	asJSON := fs.Bool("json", false, "print structured checks; exit 1 if any prerequisite is missing")
	var diag diagnosticFlags
	diag.register(fs)
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usage("doctor accepts no positional arguments")
	}
	target, _, err := resolveTarget(*targetName, "")
	if err != nil {
		return usage("%v", err)
	}
	result := struct {
		Target string        `json:"target"`
		Ready  bool          `json:"ready"`
		Checks []doctorCheck `json:"checks"`
	}{Target: target.Name, Ready: true}
	check := func(name string, err error, detail string) {
		if err != nil {
			detail, result.Ready = err.Error(), false
		}
		result.Checks = append(result.Checks, doctorCheck{name, err == nil, detail})
	}
	executor := &toolchain.Executor{Stderr: io.Discard}
	probe := func(name string, args ...string) (string, error) {
		b, err := executor.Run(ctx, toolchain.Command{Tool: name, Args: args})
		return trimOutput(b), err
	}
	goVersion, err := probe("go", "version")
	if err == nil && !strings.Contains(goVersion, " go1.26.10 ") {
		err = fmt.Errorf("verified consumer linker is go1.26.10; found %s", goVersion)
	}
	check("go", err, goVersion)
	rustVersion, err := probe("rustc", "--version")
	if err == nil && !strings.HasPrefix(rustVersion, "rustc 1.99.1 ") {
		err = fmt.Errorf("verified Rust version is 1.99.1; found %s", rustVersion)
	}
	check("rustc", err, rustVersion)
	cargoVersion, err := probe("cargo", "--version")
	check("cargo", err, cargoVersion)
	libdir, err := probe("rustc", "--print", "target-libdir", "--target", target.RustTriple)
	if err == nil {
		libs, globErr := filepath.Glob(filepath.Join(libdir, "libstd-*.rlib"))
		if globErr != nil {
			err = globErr
		} else if len(libs) == 0 {
			err = fmt.Errorf("Rust std target %s is missing; install it with rustup target add %s", target.RustTriple, target.RustTriple)
		}
	}
	check("rust-target", err, libdir)
	ld := *linker
	if ld == "" {
		ld = toolchain.DefaultLinker(target)
	}
	if strings.HasPrefix(target.Name, "windows/") {
		check("linker", nil, "builtin COFF archive selection; no native partial linker")
	} else {
		path, e := exec.LookPath(ld)
		if ld == "" {
			e = fmt.Errorf("Darwin archive builds require a compatible Apple partial linker; combine on macOS or supply -ld")
		}
		check("linker", e, path+" (availability check; build validates target output)")
	}
	o := nativeFlags{sdk: *sdk, sysroot: *sysroot}
	err = resolvePlatform(ctx, &o, target, executor.Run)
	if err == nil {
		if strings.HasPrefix(target.Name, "darwin/") {
			_, err = translate.SDKImportsForArch(o.sdk, strings.TrimPrefix(target.Name, "darwin/"))
			if err == nil {
				_, err = toolchain.SDKVersion(o.sdk)
			}
		} else if !strings.HasPrefix(target.Name, "windows/") {
			err = linuxelf.ValidateSysrootTarget(o.sysroot, strings.TrimPrefix(target.Name, "linux/"))
		}
	}
	check("system-imports", err, o.sdk+o.sysroot)
	if err := ctx.Err(); err != nil {
		return err
	}
	if diag.enabled() {
		d := newDiagnosticSession(diag, "doctor", target.Name, "", stderr)
		for _, c := range result.Checks {
			status := "OK"
			if !c.OK {
				status = "FAIL"
			}
			d.stage(c.Name, status, c.Detail, nil, nil)
		}
		if strings.HasPrefix(target.Name, "linux/") {
			if libraries, err := linuxelf.SearchableLibraries(o.sysroot, strings.TrimPrefix(target.Name, "linux/")); err != nil {
				d.skip("library-search", err.Error())
			} else {
				d.stage("library-search", "OK", fmt.Sprintf("%d shared objects searchable: %s", len(libraries), strings.Join(libraries, ", ")), nil, nil)
			}
		} else {
			d.skip("library-search", "only Linux sysroots are enumerated")
		}
		d.report.Result = fmt.Sprintf("finished: ready=%v; execution not verified", result.Ready)
		if d.printing() {
			fmt.Fprintln(stderr, d.report.Result)
		}
		d.close()
	}
	if *asJSON {
		if err := writeJSON(stdout, result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(stdout, "Producer toolchain: %s\n", target.Name)
		for _, c := range result.Checks {
			status := "ok"
			if !c.OK {
				status = "missing/unsupported"
			}
			fmt.Fprintf(stdout, "  %-15s %-20s %s\n", c.Name, status, c.Detail)
		}
		if result.Ready {
			fmt.Fprintln(stdout, "Ready for producer builds. Link and execution still require platform verification.")
		}
	}
	if !result.Ready {
		return fmt.Errorf("producer toolchain checks failed for %s", target.Name)
	}
	return nil
}
