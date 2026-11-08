package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func registerProbe(direct bool) string {
	lines := []string{".text", ".p2align 2", ".globl _bao_tls_register_probe", "_bao_tls_register_probe:", "sub sp, sp, #240", "stp x29, x30, [sp, #224]", "add x29, sp, #224"}
	for i := 19; i < 29; i += 2 {
		lines = append(lines, fmt.Sprintf("stp x%d, x%d, [sp, #%d]", i, i+1, (i-19)*8))
	}
	for i := 8; i < 16; i += 2 {
		lines = append(lines, fmt.Sprintf("stp q%d, q%d, [sp, #%d]", i, i+1, 80+(i-8)*16))
	}
	if direct {
		lines = append(lines, "adrp x0, _bao_test_descriptor@PAGE", "add x0, x0, _bao_test_descriptor@PAGEOFF")
	} else {
		lines = append(lines, "adrp x0, _bao_tls_state@TLVPPAGE", "ldr x0, [x0, _bao_tls_state@TLVPPAGEOFF]")
	}
	var regs []int
	for i := 1; i < 16; i++ {
		regs = append(regs, i)
	}
	for i := 19; i < 29; i++ {
		regs = append(regs, i)
	}
	for _, i := range regs {
		lines = append(lines, fmt.Sprintf("mov x%d, #%d", i, 0x100+i))
	}
	for i := 0; i < 32; i++ {
		lines = append(lines, fmt.Sprintf("movi v%d.16b, #0x35", i))
	}
	lines = append(lines, "ldr x16, [x0]", "blr x16")
	for _, i := range regs {
		lines = append(lines, fmt.Sprintf("cmp x%d, #%d", i, 0x100+i), "b.ne 1f")
	}
	lines = append(lines, "movz x16, #0x3535")
	for _, shift := range []int{16, 32, 48} {
		lines = append(lines, fmt.Sprintf("movk x16, #0x3535, lsl #%d", shift))
	}
	for i := 0; i < 32; i++ {
		for lane := 0; lane < 2; lane++ {
			lines = append(lines, fmt.Sprintf("umov x17, v%d.d[%d]", i, lane), "cmp x17, x16", "b.ne 1f")
		}
	}
	lines = append(lines, "mov x0, #1", "b 2f", "1: mov x0, #0", "2:")
	for i := 19; i < 29; i += 2 {
		lines = append(lines, fmt.Sprintf("ldp x%d, x%d, [sp, #%d]", i, i+1, (i-19)*8))
	}
	for i := 8; i < 16; i += 2 {
		lines = append(lines, fmt.Sprintf("ldp q%d, q%d, [sp, #%d]", i, i+1, 80+(i-8)*16))
	}
	lines = append(lines, "ldp x29, x30, [sp, #224]", "add sp, sp, #240", "ret")
	return strings.Join(lines, "\n") + "\n"
}

func clobberLookup() string {
	lines := []string{".data", ".p2align 3", "_bao_test_descriptor:", ".quad _bao_tls_thunk", ".quad 0", ".quad 0", ".text", ".p2align 2", ".globl _bao_tls_lookup", "_bao_tls_lookup:"}
	for i := 1; i < 16; i++ {
		lines = append(lines, fmt.Sprintf("mov x%d, #0x777", i))
	}
	for i := 0; i < 32; i++ {
		if i >= 8 && i < 16 {
			lines = append(lines, fmt.Sprintf("ins v%d.d[1], x1", i))
		} else {
			lines = append(lines, fmt.Sprintf("movi v%d.16b, #0x77", i))
		}
	}
	return strings.Join(append(lines, "mov x0, #42", "ret"), "\n") + "\n"
}

func (h *harness) tls() {
	check(runtime.GOOS == "darwin" && (h.target == "darwin/arm64" || h.target == "darwin/amd64"), "TLS ABI suite requires macOS")
	arch := strings.TrimPrefix(h.target, "darwin/")
	h.env["GOOS"] = "darwin"
	h.env["GOARCH"] = arch
	h.results["target"] = h.target
	clangTarget, ldarch, rustTarget := "arm64-apple-macos11", "arm64", "aarch64-apple-darwin"
	probeSource, clobberSource := registerProbe, clobberLookup
	nativeDir := "translate/native"
	negativeFrom, negativeTo := "    ldp q0, q1, [sp, #128]", "    nop // negative control"
	accessor := "#include \"textflag.h\"\nTEXT ·SymbolAddr0(SB),NOSPLIT,$0-8\n MOVD $bao_tls_register_probe(SB),R0\n MOVD R0,ret+0(FP)\n RET\n"
	if arch == "amd64" {
		clangTarget, ldarch, rustTarget = "x86_64-apple-macos11", "x86_64", "x86_64-apple-darwin"
		probeSource, clobberSource = registerProbeAMD64, clobberLookupAMD64
		nativeDir += "/amd64"
		negativeFrom, negativeTo = "    fxrstor64 (%rsp)", "    nop // negative control"
		accessor = "#include \"textflag.h\"\nTEXT ·SymbolAddr0(SB),NOSPLIT,$0-8\n MOVQ $bao_tls_register_probe(SB),AX\n MOVQ AX,ret+0(FP)\n RET\n"
	}
	dir := filepath.Join(h.dst, "tls")
	require(os.MkdirAll(dir, 0o755))
	compile := func(source, output string) {
		h.run(filepath.Base(output)+"-compile.log", h.root, nil, "/usr/bin/clang", "-target", clangTarget, "-O2", "-c", source, "-o", output)
	}
	rust := filepath.Join(dir, "rust.o")
	h.run("tls-rust-compile.log", h.root, nil, "rustc", "--crate-type", "lib", "--emit=obj", "--edition=2024", "--target", rustTarget, "-O", filepath.Join(h.root, "testdata/tls_rust.rs"), "-o", rust)
	threads := filepath.Join(dir, "threads.o")
	compile(filepath.Join(h.root, "testdata/tls_threads.c"), threads)
	probe := filepath.Join(dir, "probe.S")
	require(os.WriteFile(probe, []byte(probeSource(false)), 0o644))
	compile(probe, filepath.Join(dir, "probe.o"))
	sdk := strings.TrimSpace(string(h.run("tls-sdk-version.log", h.root, nil, "xcrun", "--show-sdk-version")))
	combined := filepath.Join(dir, "combined.o")
	h.run("tls-combine.log", h.root, nil, "/usr/bin/ld", "-r", "-arch", ldarch, "-platform_version", "macos", "11.0", sdk, threads, filepath.Join(dir, "probe.o"), rust, "-o", combined)
	app := filepath.Join(dir, "consumer")
	h.module(app, "bao-tls-check", "")
	h.run("tls-producer.log", h.root, nil, h.bao, "probe-tls", "-symbol", "bao_tls_thread_test", "-symbol", "bao_tls_counter_next", "-o", filepath.Join(app, "native"), combined)
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(`package main
import (
    "fmt"
    "runtime"
    "bao-tls-check/native"
    "github.com/ebitengine/purego"
)
func main() {
    runtime.LockOSThread()
    var test func() int32
    var next func() uint64
    purego.RegisterFunc(&test,native.SymbolAddr0())
    purego.RegisterFunc(&next,native.SymbolAddr1())
    if test()!=0 || native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=8 { panic("worker TLS/ABI failure") }
    if next()!=42 || next()!=43 { panic("main TLS isolation") }
    native.TLSFinalizeCurrentThread()
    if native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=9 { panic("main TLS cleanup") }
    fmt.Println("PASS: TLS isolation, all SIMD/GPRs, 8 pthreads, 24 LIFO/reentrant terminators, 9 freed blocks")
}
`), 0o644))
	exe := filepath.Join(h.dst, "tls-executable")
	h.consumer("tls-link.log", app, h.goTool, "build", "-o", exe, ".")
	check(strings.Contains(string(h.consumer("tls-run.log", app, exe)), "PASS: TLS isolation"), "TLS execution failed")
	h.run("tls-sign.log", app, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
	h.run("tls-sign-verify.log", app, nil, "codesign", "--verify", "--strict", exe)
	check(strings.Contains(string(h.consumer("tls-signed-run.log", app, exe)), "PASS: TLS isolation"), "signed TLS execution failed")
	abi := filepath.Join(dir, "abi")
	require(os.Mkdir(abi, 0o755))
	source := filepath.Join(abi, "probe.S")
	require(os.WriteFile(source, []byte(probeSource(true)+clobberSource()), 0o644))
	compile(source, filepath.Join(abi, "probe.o"))
	for _, negative := range []bool{false, true} {
		name := "positive"
		if negative {
			name = "negative"
		}
		path := filepath.Join(abi, name)
		h.module(path, "bao-abi-check", "")
		native := filepath.Join(path, "native")
		require(os.Mkdir(native, 0o755))
		copyFile(filepath.Join(abi, "probe.o"), filepath.Join(native, "probe_darwin_"+arch+".syso"))
		if negative {
			broken := strings.Replace(string(read(filepath.Join(h.root, nativeDir+"/thunk.S"))), negativeFrom, negativeTo, 1)
			file := filepath.Join(path, "broken.S")
			require(os.WriteFile(file, []byte(broken), 0o644))
			compile(file, filepath.Join(native, "thunk_darwin_"+arch+".syso"))
		} else {
			copyFile(filepath.Join(h.root, nativeDir+"/thunk.bin"), filepath.Join(native, "thunk_darwin_"+arch+".syso"))
		}
		require(os.WriteFile(filepath.Join(native, "symbols.go"), []byte("package native\nfunc SymbolAddr0() uintptr\n"), 0o644))
		require(os.WriteFile(filepath.Join(native, "symbols.s"), []byte(accessor), 0o644))
		require(os.WriteFile(filepath.Join(path, "main.go"), []byte(`package main
import("fmt";"bao-abi-check/native";"github.com/ebitengine/purego")
func main(){var probe func()int32;purego.RegisterFunc(&probe,native.SymbolAddr0());if probe()!=1{panic("ABI register preservation failed")};fmt.Println("PASS: full SIMD/GPR preservation")}
`), 0o644))
		exe := filepath.Join(path, "executable")
		h.consumer("abi-"+name+"-link.log", path, h.goTool, "build", "-o", exe, ".")
		out, err := h.command("abi-"+name+"-run.log", path, nil, exe)
		if negative {
			check(err != nil && strings.Contains(string(out), "ABI register preservation failed"), "broken SIMD restoration was not detected")
		} else {
			require(err)
			check(strings.Contains(string(out), "PASS:"), "ABI positive control failed")
		}
	}
	h.results["tls_abi"] = map[string]any{"status": "PASS", "threads": 8, "terminators": 24, "blocks_freed": 9, "registers": "required GPRs and full 128-bit SIMD", "negative": "disabled SIMD restoration detected", "signing": "Hardened Runtime verify/rerun"}
}
