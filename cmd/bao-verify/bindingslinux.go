package main

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var scalarBindingSymbols = []string{"bao_scalar_tls_next", "bao_scalar_ints", "bao_scalar_floats", "bao_scalar_mixed", "bao_scalar_narrow", "bao_scalar_pointer", "bao_scalar_wait", "bao_scalar_u32"}

func (h *harness) bindingsLinux() {
	arch := strings.TrimPrefix(h.target, "linux/")
	check(arch == "arm64" || arch == "loong64" || arch == "ppc64le", "unsupported typed Linux target %s", h.target)
	triple, compiler, linker, qemu := "aarch64-linux-gnu", "gcc", "ar", ""
	if arch == "loong64" {
		triple, compiler, linker, qemu = "loongarch64-linux-gnu", "loongarch64-linux-gnu-gcc", "loongarch64-linux-gnu-ar", "qemu-loongarch64"
	}
	if arch == "ppc64le" {
		triple, compiler, linker, qemu = "powerpc64le-linux-gnu", "powerpc64le-linux-gnu-gcc", "powerpc64le-linux-gnu-ar", "qemu-ppc64le"
	}
	imageID := strings.TrimSpace(string(h.run("bindings-image.log", h.root, nil, "docker", "image", "inspect", h.image, "--format", "{{.Id}} {{.Architecture}}")))
	lbao := h.linuxProducer("bindings-bao-build.log")
	compile := fmt.Sprintf("set -eu\n%s --version | head -1\n%s -O2 -g -fPIC -c /src/bindings.c -o /work/bindings.o\n%s rs /work/library.a /work/bindings.o\n", compiler, compiler, linker)
	h.run("bindings-native-build.log", h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "-v", filepath.Join(h.root, "testdata/bindings_integration.c")+":/src/bindings.c:ro", "-v", h.dst+":/work", "--entrypoint", "/bin/sh", h.image, "-c", compile)
	original := filepath.Join(h.dst, "library.a")
	originalHash := digest(original)
	app := filepath.Join(h.dst, "bindings-consumer")
	require(os.Mkdir(app, 0755))
	sysroot := "/"
	if qemu != "" {
		sysroot = "/usr/" + triple
	}
	producer := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "-v", h.dst + ":/work", "--entrypoint", "/work/bao-linux", h.image, "build", "-target", h.target, "-sysroot", sysroot, "-bindings", "dwarf", "-o", "/work/bindings-consumer/native"}
	for _, s := range scalarBindingSymbols {
		producer = append(producer, "-symbol", s)
	}
	producer = append(producer, "/work/library.a")
	h.run("bindings-producer.log", h.root, nil, producer...)
	check(digest(original) == originalHash, "signature inference/stripping mutated the source archive")
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-bindings-check\n\ngo 1.26.0\n"), 0644))
	copyFile(filepath.Join(h.root, "testdata/bindings_consumer.go.tmpl"), filepath.Join(app, "main.go"))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	exe := filepath.Join(h.dst, "bindings-executable")
	h.run("bindings-consumer-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	deps := string(h.run("bindings-deps.log", app, cross, h.goTool, "list", "-deps", "."))
	check(!strings.Contains(deps, "github.com/ebitengine/purego"), "fixed-signature consumer retained the purego module")
	info := string(h.run("bindings-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0") && !strings.Contains(info, "github.com/ebitengine/purego"), "typed consumer must build without cgo or purego module")
	for _, procs := range []string{"1", "4"} {
		args := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "-e", "GOMAXPROCS=" + procs, "-e", "CC=/bao-no-cc", "-e", "CXX=/bao-no-cxx", "-e", "RUSTC=/bao-no-rustc", "-v", h.dst + ":/work:ro"}
		if qemu == "" {
			args = append(args, "--entrypoint", "/work/bindings-executable", h.image)
		} else {
			args = append(args, "--entrypoint", "/usr/bin/"+qemu, h.image, "-L", sysroot, "/work/bindings-executable")
		}
		out := string(h.run("bindings-run-"+procs+".log", h.root, nil, args...))
		check(strings.Contains(out, "PASS: typed scalars"), "typed scalar/scheduler checks failed")
	}
	// With cgo enabled and no other cgo dependency, runtime/cgo is not linked:
	// default flags link internally and the bundled bootstrap installs its hooks
	// from runtime._cgo_init. No C compiler is available to this build.
	cgoExe := filepath.Join(h.dst, "bindings-cgo-executable")
	cgoEnv := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "1"})
	h.run("bindings-cgo-consumer-build.log", app, cgoEnv, h.goTool, "build", "-o", cgoExe, ".")
	info = string(h.run("bindings-cgo-buildinfo.log", app, nil, h.goTool, "version", "-m", cgoExe))
	check(strings.Contains(info, "CGO_ENABLED=1") && !strings.Contains(info, "-ldflags"), "cgo-enabled typed consumer must build with default flags")
	for _, procs := range []string{"1", "4"} {
		args := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "-e", "GOMAXPROCS=" + procs, "-v", h.dst + ":/work:ro"}
		if qemu == "" {
			args = append(args, "--entrypoint", "/work/bindings-cgo-executable", h.image)
		} else {
			args = append(args, "--entrypoint", "/usr/bin/"+qemu, h.image, "-L", sysroot, "/work/bindings-cgo-executable")
		}
		out := string(h.run("bindings-cgo-run-"+procs+".log", h.root, nil, args...))
		check(strings.Contains(out, "PASS: typed scalars"), "cgo-enabled typed scalar/scheduler checks failed")
	}
	artifacts, err := filepath.Glob(filepath.Join(app, "native", "*.syso"))
	require(err)
	unwind := false
	for _, path := range artifacts {
		f, err := elf.Open(path)
		require(err)
		for _, s := range f.Sections {
			check(!strings.Contains(s.Name, "debug_") && !strings.Contains(s.Name, "zdebug_"), "debug section survived typed output: %s", s.Name)
			unwind = unwind || strings.Contains(s.Name, "eh_frame")
		}
		require(f.Close())
	}
	check(unwind, "runtime unwind metadata was stripped")
	debug := readJSON(filepath.Join(app, "native", "bao-debug.json"))
	check(debug["stripped"] == true && debug["removed_sections"].(float64) > 0, "debug strip evidence missing")
	strippedFailure := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "-v", h.dst + ":/work", "--entrypoint", "/work/bao-linux", h.image, "translate", "-target", h.target, "-sysroot", sysroot, "-bindings", "dwarf", "-symbol", "bao_scalar_tls_next", "-o", "/work/must-not-infer", "/work/bindings-consumer/native/native_0_linux_" + arch + ".syso"}
	out, err := h.command("bindings-stripped-inference-negative.log", h.root, nil, strippedFailure...)
	check(err != nil && (strings.Contains(string(out), "no source-level DWARF") || strings.Contains(string(out), "no source-level DWARF signature")), "inference unexpectedly succeeded after debug stripping")
	execution := "native Linux arm64"
	if qemu != "" {
		execution = "QEMU guest execution; physical target hardware not verified"
	}
	h.results["typed_linux_bindings"] = map[string]any{"status": "PASS", "target": h.target, "image_id": imageID, "execution": execution, "cgo_enabled": "0, and 1 with default flags and no cgo dependency", "cgo_executable_sha256": digest(cgoExe), "purego_module": false, "functions": len(scalarBindingSymbols), "checks": "integer/FP spills, mixed/narrow packing, pointer round trip, uint32 extension, TLS, GOMAXPROCS1schedulerprogress, GOMAXPROCS1/4", "dwarf": "original optimized -O2/-g C archive; source immutable; inference fails after source-level debug stripping", "debug": debug, "runtime_unwind": "preserved", "source_sha256": digest(filepath.Join(h.root, "testdata/bindings_integration.c")), "archive_sha256": originalHash, "executable_sha256": digest(exe)}
	h.bindingsLinuxRust(lbao, arch, triple, sysroot, qemu)
	fmt.Println("PASS fixed-signature", h.target, "without purego module")
}

func (h *harness) bindingsLinuxRust(bao, arch, triple, sysroot, qemu string) {
	rustTarget := map[string]string{"arm64": "aarch64-unknown-linux-gnu", "loong64": "loongarch64-unknown-linux-gnu", "ppc64le": "powerpc64le-unknown-linux-gnu"}[arch]
	compile := "rustc --target " + rustTarget + " --crate-type staticlib --crate-name bao_linux_runtime --edition=2024 -O -g -Ccodegen-units=1 /src/lib.rs -o /work/rust-library.a"
	h.run("bindings-rust-native-build.log", h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "-v", filepath.Join(h.root, "examples/linux_runtime/src")+":/src:ro", "-v", h.dst+":/work", "--entrypoint", "/bin/sh", h.image, "-c", compile)
	archive := filepath.Join(h.dst, "rust-library.a")
	original := digest(archive)
	app := filepath.Join(h.dst, "rust-bindings-consumer")
	require(os.Mkdir(app, 0755))
	h.run("bindings-rust-producer.log", h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "-v", h.dst+":/work", "--entrypoint", "/work/bao-linux", h.image, "build", "-target", h.target, "-sysroot", sysroot, "-bindings", "dwarf", "-symbol", "bao_example_run", "-symbol", "bao_example_check_finalized", "-o", "/work/rust-bindings-consumer/native", "/work/rust-library.a")
	check(digest(archive) == original, "typed producer mutated the Rust archive")
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-rust-bindings-check\n\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(`package main
import("fmt";"runtime";"bao-rust-bindings-check/native")
func main(){runtime.LockOSThread();if got:=native.BaoExampleRun();got!=42{panic(fmt.Sprintf("Rust runtime=%d",got))};native.TLSFinalizeCurrentThread();if native.BaoExampleCheckFinalized()!=42||native.TLSLiveBlocks()!=0||native.TLSDestroyedBlocks()!=9{panic("Rust TLS destruction")};fmt.Println("PASS: optimized Rust std typed bindings, panic/2 RAII drops/8 native threads/9 TLS drops, live0 freed9; native debug stripped; no purego module")}
`), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	exe := filepath.Join(h.dst, "bindings-rust-executable")
	h.run("bindings-rust-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	deps := string(h.run("bindings-rust-deps.log", app, cross, h.goTool, "list", "-deps", "."))
	check(!strings.Contains(deps, "github.com/ebitengine/purego"), "Rust fixed-signature consumer imports purego")
	for _, procs := range []string{"1", "4"} {
		args := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "-e", "GOMAXPROCS=" + procs, "-v", h.dst + ":/work:ro"}
		if qemu == "" {
			args = append(args, "--entrypoint", "/work/bindings-rust-executable", h.image)
		} else {
			args = append(args, "--entrypoint", "/usr/bin/"+qemu, h.image, "-L", sysroot, "/work/bindings-rust-executable")
		}
		out := string(h.run("bindings-rust-run-"+procs+".log", h.root, nil, args...))
		check(strings.Contains(out, "PASS: optimized Rust std typed bindings"), "Rust runtime with stripped DWARF failed")
	}
	debug := readJSON(filepath.Join(app, "native/bao-debug.json"))
	check(debug["stripped"] == true && debug["removed_sections"].(float64) > 0, "optimized Rust debug was not stripped")
	h.results["typed_linux_rust"] = map[string]any{"status": "PASS", "target": h.target, "source_sha256": digest(filepath.Join(h.root, "examples/linux_runtime/src/lib.rs")), "archive_sha256": original, "executable_sha256": digest(exe), "debug": debug, "runtime": "caught panic/2 RAII drops/8 native threads/9 TLS destructors after stripping; GOMAXPROCS1/4", "purego_module": false}
}
