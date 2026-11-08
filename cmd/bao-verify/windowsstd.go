package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The GNU Rust std profile is gated independently of the C++ fixtures. Rust's
// staticlib includes std; matching native unwind/CRT wrapper archives close it.
func (h *harness) windowsStd(arch string) {
	check(h.staticWindows, "Windows Rust std requires the prepared static runtime profile")
	sysroot := strings.TrimSpace(string(h.run("windows-std-sysroot.log", h.root, nil, "rustc", "--print", "sysroot")))
	notices := append([]string{}, h.staticLinkNotices...)
	notices = append(notices, filepath.Join(sysroot, "share/doc/rust/COPYRIGHT-library.html"))
	dir := filepath.Join(sysroot, "share/doc/rust/licenses")
	files, err := os.ReadDir(dir)
	require(err)
	check(len(files) > 0, "Rust library licenses are missing")
	for _, f := range files {
		if !f.IsDir() {
			notices = append(notices, filepath.Join(dir, f.Name()))
		}
	}
	results := map[string]any{}
	nativeControl := "PASS: ordinary native linker and OS TLS"
	for _, mode := range []string{"manifest", "runtime"} {
		prefix := "windows-std-" + mode
		app := filepath.Join(h.dst, "rust-std-"+mode)
		require(os.Mkdir(app, 0755))
		args := []string{h.bao, "build", "-target", h.target, "-manifest-path", filepath.Join(h.root, "examples/windows_std/Cargo.toml"), "-offline", "-locked", "-o", filepath.Join(app, "native")}
		if mode == "manifest" {
			args = append(args, "-bindings", filepath.Join(h.root, "examples/windows_std/signatures.json"))
		}
		for _, s := range []string{"run", "check", "counts"} {
			args = append(args, "-symbol", "bao_windows_std_"+s)
		}
		args = h.staticWindowsBuildArgs(args)
		for _, notice := range notices[len(h.staticLinkNotices):] {
			args = append(args, "-link-notice", notice)
		}
		h.run(prefix+"-producer.log", h.root, nil, args...)
		for i, notice := range notices {
			check(digest(notice) == digest(filepath.Join(app, "native", fmt.Sprintf("bao-linked-license-%d.txt", i))), "Rust std license changed or omitted")
		}
		provenance := readJSON(filepath.Join(app, "native/bao-build.json"))
		archive := provenance["source"].(string)
		archiveHash := digest(archive)
		check(archiveHash == provenance["source_sha256"], "Rust std source provenance mismatch")
		if mode == "manifest" {
			control := filepath.Join(h.dst, "rust-std-control.exe")
			ccArgs := []string{h.windowsCC, "-O2", filepath.Join(h.root, "testdata/windows_std_control.c"), archive, "-static", "-o", control}
			ccArgs = append(ccArgs, h.staticLinkArchives...)
			ccArgs = append(ccArgs, "-lntdll", "-lws2_32", "-luserenv", "-lbcryptprimitives", "-lsynchronization", "-ladvapi32")
			h.run("windows-std-native-link.log", h.root, nil, ccArgs...)
			out, err := h.command("windows-std-native-run.log", h.root, nil, h.windowsExecute(control)...)
			if err != nil && h.windowsRunner != "" && arch == "arm64" && strings.TrimSpace(string(out)) == "native result=3 tls=8 unwind=0 lock=8 failures=2 fls=2" && nativePEThreadAlignment(control) == 128 {
				// Wine 10 alloc_thread_tls uses ordinary heap allocation and
				// ignores the PE TLS directory's requested 128-byte alignment.
				// Keep this recorded as an execution failure, never a native pass.
				nativeControl = "FAIL_ALIGNMENT_UNDER_WINE: native PE requests 128-byte TLS alignment; only alignment check failed; native Windows must pass"
			} else {
				require(err)
				check(strings.Contains(string(out), "PASS: native Windows Rust std control"), "native Rust std control failed")
			}
		}
		source := windowsStdConsumer
		if mode == "manifest" {
			require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-windows-std\ngo 1.26.0\n"), 0644))
			source = strings.Replace(source, "BINDINGS", "run,check,counts:=native.Run,native.Check,native.Counts", 1)
			source = strings.Replace(source, "PUREGO_IMPORT", "", 1)
		} else {
			h.module(app, "bao-windows-std", "")
			source = strings.Replace(source, "BINDINGS", "var run,check func()uint64;var counts func(uint64)uint64;purego.RegisterFunc(&run,native.SymbolAddr0());purego.RegisterFunc(&check,native.SymbolAddr1());purego.RegisterFunc(&counts,native.SymbolAddr2())", 1)
			source = strings.Replace(source, "PUREGO_IMPORT", `"github.com/ebitengine/purego"`, 1)
		}
		require(os.WriteFile(filepath.Join(app, "main.go"), []byte(source), 0644))
		exe := filepath.Join(h.dst, "rust-std-"+mode+".exe")
		cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
		h.run(prefix+"-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
		checkWindowsFunctionTable(exe, arch)
		f, err := pe.Open(exe)
		require(err)
		libs, err := windowsImportedLibraries(f)
		require(err)
		require(f.Close())
		for _, lib := range libs {
			check(!languageRuntimeLibrary(lib), "Rust std retains shared language runtime %s", lib)
		}
		for _, procs := range []string{"1", "4"} {
			out := h.run(prefix+"-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
			check(strings.Contains(string(out), "PASS: Windows Rust std"), "Rust std execution failed")
		}
		for _, kind := range []string{"tls", "constructors", "unwind"} {
			negative := filepath.Join(h.dst, "rust-std-"+mode+"-negative-"+kind)
			copyTree(app, negative)
			path := filepath.Join(negative, "main.go")
			code := string(read(path))
			switch kind {
			case "tls":
				code = strings.ReplaceAll(code, "native.TLSFinalizeCurrentThread()", "")
			case "constructors":
				path = filepath.Join(negative, "native/symbols_windows_"+arch+".go")
				code = string(read(path))
				check(strings.Contains(code, "callConstructor(p)"), "Rust std constructor call missing")
				code = strings.ReplaceAll(code, "callConstructor(p)", "func(uintptr){}(p)")
			case "unwind":
				disableWindowsUnwind(negative, arch)
			}
			require(os.WriteFile(path, []byte(code), 0644))
			negativeExe := filepath.Join(h.dst, "rust-std-"+mode+"-negative-"+kind+".exe")
			h.run(prefix+"-negative-"+kind+"-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
			out, err := h.command(prefix+"-negative-"+kind+"-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
			check(err != nil && strings.Contains(string(out), "Windows Rust std") && !strings.Contains(string(out), "PASS:"), "Rust std %s negative was not detected: %v %s", kind, err, out)
		}
		check(digest(archive) == archiveHash, "Rust std verification modified native input")
		results[mode] = map[string]any{"status": "PASS", "archive_sha256": archiveHash, "executable_sha256": digest(exe), "libraries": libs, "notices": len(notices), "negatives": []string{"caller TLS cleanup", "constructors", "unwind lookup before panic"}}
	}
	h.results["windows_rust_std"] = map[string]any{"modes": results, "native_control": nativeControl, "threads": 8, "tls_destructors": 9, "unwind_drops": 2, "features": []string{"allocation", "mutex/barrier", "HashMap/OS randomness", "args/current directory", "temporary-file I/O", "native TLS", "FLS get/set/free callbacks", "catch_unwind"}, "boundaries": "GNU Rust targets, one image, explicit locked-thread cleanup and Shutdown; no Rust unwind through Go"}
}

func nativePEThreadAlignment(path string) uint32 {
	f, err := pe.Open(path)
	require(err)
	defer f.Close()
	o, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	check(ok, "native control must be PE32+")
	d := o.DataDirectory[9]
	for _, s := range f.Sections {
		if d.VirtualAddress < s.VirtualAddress {
			continue
		}
		offset := uint64(d.VirtualAddress - s.VirtualAddress)
		if offset+40 <= uint64(s.Size) && d.Size >= 40 {
			data, err := s.Data()
			require(err)
			bits := binary.LittleEndian.Uint32(data[offset+36:]) >> 20 & 15
			if bits > 0 {
				return 1 << (bits - 1)
			}
		}
	}
	return 0
}

const windowsStdConsumer = `package main
import("fmt";"runtime";native "bao-windows-std/native";PUREGO_IMPORT)
func main(){
 runtime.LockOSThread()
 BINDINGS
 if v:=run();v!=42{panic(fmt.Sprintf("Windows Rust std run %d",v))}
 if counts(0)!=8 || counts(1)!=2 || counts(2)!=8 || counts(3)!=0 || counts(4)!=2 {panic("Windows Rust std worker cleanup")}
 native.TLSFinalizeCurrentThread()
 if check()!=42 || counts(0)!=9 || native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=9 {panic("Windows Rust std caller TLS cleanup")}
 native.Shutdown();native.Shutdown()
 fmt.Println("PASS: Windows Rust std allocation/threads/TLS/catch_unwind/I/O")
}
`
