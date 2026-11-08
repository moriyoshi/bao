package main

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// releaseSmoke exercises the selected packaged executable once end-to-end.
// The full source suite is a separate content-addressed prerequisite.
func (h *harness) releaseSmoke() {
	parts := strings.Split(h.target, "/")
	check(len(parts) == 2, "invalid release smoke target")
	goos, arch := parts[0], parts[1]
	app := filepath.Join(h.dst, "consumer")
	require(os.Mkdir(app, 0755))
	archive := filepath.Join(h.dst, "smoke.a")
	args := []string{"build", "-target", h.target, "-bindings", "dwarf", "-symbol", "bao_release_check"}
	var execute func(string, string)
	if goos == "darwin" {
		check(arch == "arm64" || arch == "amd64", "unsupported Darwin smoke target")
		f, err := macho.Open(h.bao)
		require(err)
		cpu := macho.CpuArm64
		if arch == "amd64" {
			cpu = macho.CpuAmd64
		}
		check(f.Cpu == cpu, "release smoke requires the selected target CLI, not a rebuilt producer")
		require(f.Close())
		triple := "arm64-apple-macos11"
		if arch == "amd64" {
			triple = "x86_64-apple-macos11"
		}
		obj := filepath.Join(h.dst, "smoke.o")
		h.run("smoke-native-compile.log", h.root, nil, "clang", "-target", triple, "-std=c11", "-O2", "-g", "-fPIC", "-fno-omit-frame-pointer", "-c", filepath.Join(h.root, "testdata/release_smoke.c"), "-o", obj)
		h.run("smoke-archive.log", h.root, nil, "ar", "rcs", archive, obj)
		h.run("smoke-producer.log", h.root, nil, append([]string{h.bao}, append(args, "-o", filepath.Join(app, "native"), archive)...)...)
		execute = func(exe, log string) {
			out := h.run(log, h.root, nil, exe)
			check(strings.Contains(string(out), "PASS: packaged Bao"), "packaged consumer failed")
		}
	} else {
		check(goos == "linux", "unsupported release smoke OS")
		machine := map[string]elf.Machine{"arm64": elf.EM_AARCH64, "amd64": elf.EM_X86_64, "loong64": elf.EM_LOONGARCH, "ppc64le": elf.EM_PPC64}[arch]
		check(machine != elf.EM_NONE, "unsupported Linux smoke architecture")
		f, err := elf.Open(h.bao)
		require(err)
		check(f.Machine == machine, "release smoke requires the selected target CLI, not a rebuilt producer")
		require(f.Close())
		selected := filepath.Join(h.dst, "bao-selected")
		copyFile(h.bao, selected)
		require(os.Chmod(selected, 0755))
		container := []string{"docker", "run", "--rm", "--pull=never", "--platform", cppLinuxPlatform(arch), "--network", "none", "-v", h.dst + ":/work", "-v", filepath.Join(h.root, "testdata") + ":/testdata:ro"}
		prefix := ""
		if triple := cppLinuxTriple(arch); triple != "" {
			prefix = triple + "-"
			args = append(args, "-ld", triple+"-ld")
		}
		compile := prefix + "gcc -std=c11 -O2 -g -fPIC -fno-omit-frame-pointer -c /testdata/release_smoke.c -o /work/smoke.o\n" + prefix + "ar rcs /work/smoke.a /work/smoke.o"
		h.run("smoke-native-compile.log", h.root, nil, append(append([]string{}, container...), "--entrypoint", "/bin/sh", h.image, "-c", "set -eu\n"+compile)...)
		producer := append([]string{}, container...)
		if cppLinuxTriple(arch) != "" {
			producer = append(producer, "--entrypoint", "/usr/bin/"+cppLinuxQEMU(arch), h.image, "-L", cppLinuxSysroot(arch), "/work/bao-selected")
		} else {
			producer = append(producer, "--entrypoint", "/work/bao-selected", h.image)
		}
		args = append(args, "-sysroot", cppLinuxSysroot(arch), "-o", "/work/consumer/native", "/work/smoke.a")
		h.run("smoke-producer.log", h.root, nil, append(producer, args...)...)
		execute = func(exe, log string) {
			out := h.run(log, h.root, nil, h.cppLinuxExec(arch, filepath.Base(exe), "1", nil)...)
			check(strings.Contains(string(out), "PASS: packaged Bao"), "packaged consumer failed")
		}
	}
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-release-smoke\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(`package main
import("fmt"; "runtime"; "bao-release-smoke/native")
func main() {
 runtime.LockOSThread()
 if native.BaoReleaseCheck(42) != 42 { panic("packaged native constructor/TLS/call") }
 native.TLSFinalizeCurrentThread()
 if native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=1 { panic("packaged native cleanup") }
 fmt.Println("PASS: packaged Bao translation/linkage/constructor/TLS/typed call/cleanup")
}
`), 0644))
	exe := filepath.Join(h.dst, "smoke-executable")
	h.run("smoke-consumer-build.log", app, h.consumerEnv(map[string]string{"GOOS": goos, "GOARCH": arch}), h.goTool, "build", "-o", exe, ".")
	info := string(h.run("smoke-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0") && !strings.Contains(info, puregoModule), "smoke requires typed bindings with cgo disabled and no purego module")
	execute(exe, "smoke-run.log")
	if goos == "darwin" {
		h.run("smoke-sign.log", h.root, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
		h.run("smoke-sign-verify.log", h.root, nil, "codesign", "--verify", "--strict", exe)
		execute(exe, "smoke-signed-run.log")
	}
	h.results["release_smoke"] = map[string]any{"status": "PASS", "target": h.target, "selected_cli_sha256": digest(h.bao), "source_sha256": digest(filepath.Join(h.root, "testdata/release_smoke.c")), "consumer_sha256": digest(exe), "scope": "fresh selected CLI translation, constructor, native TLS and typed call; full source gates reused separately"}
	fmt.Println("PASS: selected release CLI", h.target)
}
