// bao-native regenerates Bao's authored native helpers and provenance manifests.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	root := flag.String("root", os.Getenv("BUILD_WORKSPACE_DIRECTORY"), "Bao source workspace (defaults to Bazel workspace/current directory)")
	target := flag.String("target", runtime.GOOS+"/"+runtime.GOARCH, "native helper target; Linux cross builds require the matching GNU compiler/linker")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no positional arguments accepted")
		os.Exit(2)
	}
	if *root == "" {
		var err error
		*root, err = os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := build(ctx, *root, *target); err != nil {
		fmt.Fprintln(os.Stderr, "bao-native:", err)
		os.Exit(1)
	}
}

func build(ctx context.Context, root, target string) error {
	if strings.HasPrefix(target, "windows/") {
		return buildWindows(ctx, root, target)
	}
	linux := strings.HasPrefix(target, "linux/")
	if !linux && runtime.GOOS != "darwin" {
		return fmt.Errorf("Darwin helper regeneration requires macOS")
	}
	native := filepath.Join(root, "translate/native")
	compiler := "/usr/bin/clang"
	flags := []string{"-target", "arm64-apple-macos11", "-O2", "-c"}
	outputs := []string{"tls.bin", "thunk.bin"}
	sources := []string{"tls.c", "thunk.S"}
	if target == "darwin/amd64" {
		native = filepath.Join(native, "amd64")
		sources = []string{"../tls.c", "thunk.S"}
		flags = []string{"-target", "x86_64-apple-macos11", "-O2", "-c"}
	}
	linker := "ld"
	if linux {
		native = filepath.Join(root, "linuxelf/native")
		compiler = "gcc"
		flags = []string{"-O2", "-fPIC", "-fno-omit-frame-pointer", "-mno-outline-atomics", "-c"}
		outputs = []string{"tls.o", "thunk.o"}
		triples := map[string]string{"linux/amd64": "x86_64-linux-gnu", "linux/arm64": "aarch64-linux-gnu", "linux/loong64": "loongarch64-linux-gnu", "linux/ppc64le": "powerpc64le-linux-gnu"}
		triple, ok := triples[target]
		if !ok {
			return fmt.Errorf("unsupported target %s", target)
		}
		if target != runtime.GOOS+"/"+runtime.GOARCH {
			compiler = triple + "-gcc"
			linker = triple + "-ld"
		}
		if target != "linux/arm64" {
			native = filepath.Join(native, strings.TrimPrefix(target, "linux/"))
			sources = []string{"../tls.c"}
			outputs = []string{"runtime.bin"}
			flags = []string{"-O2", "-fPIC", "-fno-omit-frame-pointer", "-c"}
			if target == "linux/ppc64le" || target == "linux/amd64" {
				sources = []string{"../tls.c", "thunk.S"}
				outputs = []string{"tls.o", "thunk.o"}
			}
		}
	} else if target != "darwin/arm64" && target != "darwin/amd64" {
		return fmt.Errorf("unsupported target %s", target)
	}
	work, err := os.MkdirTemp("", "bao-native-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	run := func(name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		b, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %w\n%s", name, err, b)
		}
		return b, nil
	}
	for i, source := range sources {
		args := append(append([]string{}, flags...), filepath.Join(native, source), "-o", filepath.Join(work, outputs[i]))
		if _, err := run(compiler, args...); err != nil {
			return err
		}
	}
	if target == "linux/arm64" || target == "linux/ppc64le" || target == "linux/amd64" {
		if _, err := run(linker, "-r", filepath.Join(work, "tls.o"), filepath.Join(work, "thunk.o"), "-o", filepath.Join(work, "runtime.bin")); err != nil {
			return err
		}
		outputs = []string{"runtime.bin"}
	}
	files := map[string]string{}
	for _, name := range outputs {
		b, err := os.ReadFile(filepath.Join(work, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(native, name), b, 0o644); err != nil {
			return err
		}
	}
	for _, name := range append(sources, outputs...) {
		b, err := os.ReadFile(filepath.Join(native, name))
		if err != nil {
			return err
		}
		files[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	version, err := run(compiler, "--version")
	if err != nil {
		return err
	}
	manifest := map[string]any{"compiler": string(version), "flags": flags, "files": files}
	if linux {
		manifest["target"] = target
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(native, "manifest.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("Regenerated native helpers:", native)
	return nil
}

func buildWindows(ctx context.Context, root, target string) error {
	arch := strings.TrimPrefix(target, "windows/")
	triple := map[string]string{"amd64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}[arch]
	if triple == "" {
		return fmt.Errorf("unsupported target %s", target)
	}
	native := filepath.Join(root, "pecoff/native")
	flags := []string{"--target=" + triple, "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-funwind-tables"}
	if arch == "arm64" {
		flags = append(flags, "-mno-outline-atomics")
	}
	compiler := "clang"
	args := append(append([]string{}, flags...), "-c", filepath.Join(native, "runtime.c"), "-o", filepath.Join(native, arch, "runtime.bin"))
	cmd := exec.CommandContext(ctx, compiler, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", compiler, err, out)
	}
	version, err := exec.CommandContext(ctx, compiler, "--version").CombinedOutput()
	if err != nil {
		return err
	}
	files := map[string]string{}
	for _, name := range []string{"../runtime.c", "runtime.bin"} {
		b, err := os.ReadFile(filepath.Join(native, arch, name))
		if err != nil {
			return err
		}
		files[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	b, err := json.MarshalIndent(map[string]any{"target": target, "compiler": string(version), "flags": flags, "files": files}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(native, arch, "manifest.json"), append(b, '\n'), 0644); err != nil {
		return err
	}
	fmt.Println("Regenerated native helpers:", filepath.Join(native, arch))
	return nil
}
