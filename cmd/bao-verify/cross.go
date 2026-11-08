package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// linuxCross exercises actual guest execution, separately from the native
// arm64 suite. QEMU results are explicitly labeled as emulated hardware.
func (h *harness) linuxCross() {
	check(h.target == "linux/loong64" || h.target == "linux/ppc64le", "linux-cross requires -target linux/loong64 or linux/ppc64le")
	arch := strings.TrimPrefix(h.target, "linux/")
	triple, rust, qemu := "loongarch64-linux-gnu", "loongarch64-unknown-linux-gnu", "qemu-loongarch64"
	if arch == "ppc64le" {
		triple, rust, qemu = "powerpc64le-linux-gnu", "powerpc64le-unknown-linux-gnu", "qemu-ppc64le"
	}
	imageID := strings.TrimSpace(string(h.run("cross-image.log", h.root, nil, "docker", "image", "inspect", h.image, "--format", "{{.Id}} {{.Architecture}}")))
	h.linuxProducer("cross-bao-build.log")
	compile := fmt.Sprintf(`set -eu
rustc --version
%s-gcc --version | head -1
%s-ld --version | head -1
%s --version | head -1
rustc --target %s --crate-type staticlib --crate-name bao_linux_runtime --edition=2024 -O /src/lib.rs -o /work/library.a
`, triple, triple, qemu, rust)
	if arch == "ppc64le" {
		compile += triple + "-gcc -c /register-probe.S -o /work/register-probe.o\n" + triple + "-ar rs /work/library.a /work/register-probe.o\n"
	}
	buildOutput := string(h.run("cross-native-build.log", h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "-v", filepath.Join(h.root, "testdata/ppc_tls_registers.S")+":/register-probe.S:ro", "-v", filepath.Join(h.root, "examples/linux_runtime/src")+":/src:ro", "-v", h.dst+":/work", "--entrypoint", "/bin/sh", h.image, "-c", compile))
	check(strings.Contains(buildOutput, "rustc 1.99.1 "), "cross suite requires Rust 1.99.1")
	app := filepath.Join(h.dst, "cross-consumer")
	h.module(app, "bao-cross-example", "")
	producer := []string{"docker", "run", "--rm", "--pull=never", "--network", "none", "-v", h.dst + ":/work", "--entrypoint", "/work/bao-linux", h.image, "build", "-target", h.target, "-sysroot", "/usr/" + triple, "-symbol", "bao_example_run", "-symbol", "bao_example_check_finalized", "-o", "/work/cross-consumer/native"}
	if arch == "ppc64le" {
		producer = append(producer, "-symbol", "bao_ppc_tls_register_test")
	}
	producer = append(producer, "/work/library.a")
	h.run("cross-producer.log", h.root, nil, producer...)
	sourceMain := `package main
import (
    "fmt"
    "runtime"
    "bao-cross-example/native"
    "github.com/ebitengine/purego"
)
func main() {
    runtime.LockOSThread()
    var run, check func() uint64
    purego.RegisterFunc(&run,native.SymbolAddr0())
    purego.RegisterFunc(&check,native.SymbolAddr1())
    PROBE
    if got:=run();got!=42{panic(fmt.Sprintf("native result=%d",got))}
    native.TLSFinalizeCurrentThread()
    if check()!=42||native.TLSLiveBlocks()!=0||native.TLSDestroyedBlocks()!=9{panic(fmt.Sprintf("native TLS cleanup: live=%d freed=%d",native.TLSLiveBlocks(),native.TLSDestroyedBlocks()))}
    fmt.Printf("PASS: Linux %s panic/2 RAII drops/8 threads/9 TLS drops; late pthread cleanup, constructors, libc callback, data, alignment; live=0 freed=9\n",runtime.GOARCH)
}
`
	probe := ""
	if arch == "ppc64le" {
		probe = "var registers func()uint64; purego.RegisterFunc(&registers,native.SymbolAddr2()); if registers()!=42 { panic(\"PPC TLS FP/VSX/R2 preservation\") }"
	}
	sourceMain = strings.ReplaceAll(sourceMain, "PROBE", probe)
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(sourceMain), 0644))
	exe := filepath.Join(h.dst, "cross-executable")
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	h.run("cross-consumer-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	info := string(h.run("cross-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0") && strings.Contains(info, "GOARCH="+arch) && strings.Contains(info, puregoVersion) && !strings.Contains(info, "=>"), "consumer must use stock Go, cgo disabled, and downloaded pinned purego")
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-cross-example", true)
	h.saveJSON("cross-alignment.json", alignment)
	execute := func(exe, log, procs string, negative bool) {
		out, err := h.command(log, h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "-e", "GOMAXPROCS="+procs, "-e", "CC=/bao-no-cc", "-e", "CXX=/bao-no-cxx", "-e", "RUSTC=/bao-no-rustc", "-v", h.dst+":/work:ro", "--entrypoint", "/usr/bin/"+qemu, h.image, "-L", "/usr/"+triple, "/work/"+filepath.Base(exe))
		if negative {
			check(err != nil && strings.Contains(string(out), "failed to initiate panic") && !strings.Contains(string(out), "PASS:"), "cross unwind negative control did not abort as expected")
		} else {
			require(err)
			check(strings.Contains(string(out), "PASS: Linux "+arch), "cross execution failed")
		}
	}
	for _, procs := range []string{"1", "4"} {
		execute(exe, "cross-run-"+procs+".log", procs, false)
	}
	negative := filepath.Join(h.dst, "cross-negative")
	copyTree(app, negative)
	path := filepath.Join(negative, "native/symbols_linux_"+arch+".go")
	source := string(read(path))
	check(strings.Contains(source, "registerFrame(unwindAddress"), "no FDE registration to disable")
	require(os.WriteFile(path, []byte(strings.ReplaceAll(source, "registerFrame(unwindAddress", "func(uintptr) {}(unwindAddress")), 0644))
	negexe := filepath.Join(h.dst, "cross-negative-executable")
	h.run("cross-negative-build.log", negative, cross, h.goTool, "build", "-o", negexe, ".")
	execute(negexe, "cross-negative-run.log", "1", true)
	if arch == "ppc64le" {
		clobbered := filepath.Join(h.dst, "cross-cabi-clobber")
		copyTree(app, clobbered)
		poisonPPCResolver(filepath.Join(clobbered, "native"), false)
		clobberExe := filepath.Join(h.dst, "cross-cabi-clobber-executable")
		h.run("cross-cabi-clobber-build.log", clobbered, cross, h.goTool, "build", "-o", clobberExe, ".")
		execute(clobberExe, "cross-cabi-clobber-run.log", "1", false)
		broken := filepath.Join(h.dst, "cross-broken-vsx")
		copyTree(clobbered, broken)
		poisonPPCResolver(filepath.Join(broken, "native"), true)
		brokenExe := filepath.Join(h.dst, "cross-broken-vsx-executable")
		h.run("cross-broken-vsx-build.log", broken, cross, h.goTool, "build", "-o", brokenExe, ".")
		out, err := h.command("cross-broken-vsx-run.log", h.root, nil, "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "-e", "GOMAXPROCS=1", "-v", h.dst+":/work:ro", "--entrypoint", "/usr/bin/"+qemu, h.image, "-L", "/usr/"+triple, "/work/"+filepath.Base(brokenExe))
		check(err != nil && strings.Contains(string(out), "PPC TLS FP/VSX/R2 preservation") && !strings.Contains(string(out), "PASS:"), "broken VSX restoration was not detected")
		h.results["ppc_tls_abi"] = "PASS: all64 full128bitVSX patterns; local/globalentryR2cookie; simulatedC-conformingVSR0clobber survives; removingVSR0restore stilllinksandfailsprobe"
	}
	manifest := readJSON(filepath.Join(app, "native/bao-manifest.json"))
	h.results["linux_cross"] = map[string]any{"status": "PASS", "target": h.target, "rust_target": rust, "image": h.image, "image_id": imageID, "execution": "QEMU user-mode guest execution in read-only/no-network Linux container; GOMAXPROCS=1/4; physical target hardware not verified", "producer": "bao build from independent Rust std archive with target GNU ld", "runtime": "panic caught, 2 RAII drops, 8 threads, 9 TLS drops; late pthread cleanup retains original TLS state/address; live=0 freed=9", "tls_descriptors": manifest["tls_descriptors"], "local_pointer_fixups": len(manifest["local_pointer_fixups"].([]any)), "alignments_checked": len(alignment), "native_unwind_negative": "PASS: same native bytes link but panic aborts without FDE registration", "source_sha256": digest(filepath.Join(h.root, "examples/linux_runtime/src/lib.rs")), "executable_sha256": digest(exe), "boundaries": "documented single-image glibc profile; native target hardware, other TLS access models, arbitrary DSO lifecycle, static musl and cross-image destructor interleaving unverified"}
	fmt.Println("PASS", h.target, "under QEMU")
}

// Model a C-conforming lookup's volatile VSR0 clobber at its return checkpoint.
// The positive copy retains the TLS thunk's restoration; the negative copy
// removes one restoration. Both must still link with identical native layout.
func poisonPPCResolver(dir string, broken bool) {
	path := filepath.Join(dir, "native_1_linux_ppc64le.syso")
	f, err := elf.Open(path)
	require(err)
	syms, err := f.Symbols()
	require(err)
	var function elf.Symbol
	for _, s := range syms {
		if strings.HasSuffix(s.Name, "_tls_resolver") && s.Section != elf.SHN_UNDEF {
			function = s
			break
		}
	}
	check(function.Size > 0, "missing PPC resolver body")
	section := f.Sections[function.Section]
	data := read(path)
	start, end := section.Offset+function.Value, section.Offset+function.Value+function.Size
	check(end <= uint64(len(data)), "invalid PPC resolver bounds")
	if !broken {
		found := false
		for _, s := range f.Sections {
			if s.Type != elf.SHT_RELA || s.Info != uint32(function.Section) {
				continue
			}
			rels, err := s.Data()
			require(err)
			for off := 0; off < len(rels); off += 24 {
				rOff, info := binary.LittleEndian.Uint64(rels[off:]), binary.LittleEndian.Uint64(rels[off+8:])
				idx := uint32(info >> 32)
				if elf.R_PPC64(uint32(info)) == elf.R_PPC64_REL24 && idx > 0 && int(idx) <= len(syms) && strings.HasSuffix(syms[idx-1].Name, "_tls_lookup") && rOff >= function.Value && rOff+8 <= function.Value+function.Size {
					place := section.Offset + rOff + 4
					check(binary.LittleEndian.Uint32(data[place:]) == 0x60000000, "missing post-C-call checkpoint")
					binary.LittleEndian.PutUint32(data[place:], 0xf00004d0)
					found = true
				}
			}
		}
		check(found, "missing native C lookup call")
	} else {
		matches := 0
		for off := start; off+4 <= end; off += 4 {
			if binary.LittleEndian.Uint32(data[off:]) == 0x7c015e98 {
				binary.LittleEndian.PutUint32(data[off:], 0x60000000)
				matches++
			}
		}
		check(matches == 1, "expected exactly one full-width VSR0 restoration")
	}
	require(f.Close())
	require(os.WriteFile(path, data, 0644))
}
