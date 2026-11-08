package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (h *harness) windowsLifecycle(arch string) {
	cxxRuntime := "auto"
	if h.windowsDriver == "clang" {
		cxxRuntime = "libc++"
	}
	if !h.staticWindows && (h.windowsDriver == "clang" || h.windowsDriver == "mingw") {
		dlls := []string{"libc++.dll", "libunwind.dll", "libwinpthread-1.dll"}
		if h.windowsDriver == "mingw" {
			dlls = []string{"libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"}
		}
		hashes := map[string]string{}
		for _, name := range dlls {
			path := ""
			if h.windowsDLLDir != "" {
				path = filepath.Join(h.windowsDLLDir, name)
			} else {
				for _, dir := range filepath.SplitList(h.env["PATH"]) {
					p := filepath.Join(dir, name)
					if st, err := os.Stat(p); err == nil && !st.IsDir() {
						path = p
						break
					}
				}
			}
			check(path != "", "matching %s is required; supply -windows-dll-dir", name)
			require(os.WriteFile(filepath.Join(h.dst, name), read(path), 0644))
			hashes[name] = digest(path)
		}
		h.results["windows_cxx_runtime_dlls"] = hashes
	} else if h.windowsDLLDir != "" {
		hashes := map[string]string{}
		for _, name := range []string{"vcruntime140.dll", "vcruntime140_1.dll", "vcruntime140_threads.dll"} {
			path := filepath.Join(h.windowsDLLDir, name)
			if _, err := os.Stat(path); err != nil {
				if name != "vcruntime140.dll" && os.IsNotExist(err) {
					continue
				}
				require(err)
			}
			require(os.WriteFile(filepath.Join(h.dst, name), read(path), 0644))
			hashes[name] = digest(path)
		}
		h.results["windows_cxx_runtime_dlls"] = hashes
	}
	objects := []string{}
	for i, source := range []string{"lifecycle.c", "lifecycle.cpp", "exceptions.cpp", "weak.c"} {
		tool := h.windowsCC
		cpp := strings.HasSuffix(source, ".cpp")
		if cpp {
			tool = h.windowsCXX
		}
		obj := filepath.Join(h.dst, fmt.Sprintf("lifecycle-%d.obj", i))
		args := h.windowsCompile(tool, filepath.Join(h.root, "examples/windows_runtime", source), obj, arch, cpp)
		if h.windowsDriver == "msvc" || h.windowsDriver == "clang-cl" {
			clean := []string{args[0], "/MD"}
			for _, a := range args[1:] {
				if a != "/Zl" {
					clean = append(clean, a)
				}
			}
			args = clean
		}
		h.run(fmt.Sprintf("windows-lifecycle-%d-compile.log", i), h.root, nil, args...)
		objects = append(objects, obj)
	}
	archive := filepath.Join(h.dst, "lifecycle.a")
	h.run("windows-lifecycle-archive.log", h.root, nil, append([]string{h.windowsAR, "rcS", archive}, objects...)...)
	archiveHash := digest(archive)
	app := filepath.Join(h.dst, "lifecycle")
	require(os.Mkdir(app, 0755))
	args := []string{h.bao, "build", "-target", h.target, "-windows-cxx-runtime", cxxRuntime, "-bindings", filepath.Join(h.root, "examples/windows_runtime/lifecycle-signatures.json"), "-o", filepath.Join(app, "native")}
	for _, s := range []string{"bao_windows_lifecycle_run", "bao_windows_lifecycle_state", "bao_windows_tls_drops", "bao_windows_tls_detaches", "bao_windows_process_events", "bao_windows_tls_address", "bao_windows_exception_run", "bao_windows_weak_run"} {
		args = append(args, "-symbol", s)
	}
	args = h.staticWindowsBuildArgs(args)
	h.run("windows-lifecycle-producer.log", h.root, nil, append(args, archive)...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-windows-lifecycle\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsLifecycleConsumer), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
	exe := filepath.Join(h.dst, "lifecycle.exe")
	h.run("windows-lifecycle-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	checkWindowsFunctionTable(exe, arch)
	for _, procs := range []string{"1", "4"} {
		out := h.run("windows-lifecycle-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
		check(strings.Contains(string(out), "PASS: Windows lifecycle"), "Windows lifecycle execution failed")
	}
	if h.windowsDriver == "clang" && !h.staticWindows {
		h.checkWindowsCgo(app, "lifecycle", arch, "bao-windows-lifecycle", "PASS: Windows lifecycle")
	}
	for _, kind := range []string{"c-init", "tls-finalize", "shutdown", "unwind"} {
		negative := filepath.Join(h.dst, "lifecycle-negative-"+kind)
		copyTree(app, negative)
		path := filepath.Join(negative, "main.go")
		code := string(read(path))
		switch kind {
		case "tls-finalize":
			code = strings.ReplaceAll(code, "native.TLSFinalizeCurrentThread()", "")
		case "shutdown":
			code = strings.ReplaceAll(code, "native.Shutdown()", "")
		case "c-init":
			path = filepath.Join(negative, "native/symbols_windows_"+arch+".go")
			code = string(read(path))
			check(strings.Contains(code, "syscall.SyscallN(p)"), "no native C initializer call")
			code = strings.ReplaceAll(code, "syscall.SyscallN(p)", "uintptr(0), uintptr(0), syscall.Errno(0)")
		case "unwind":
			disableWindowsUnwind(negative, arch)
		}
		require(os.WriteFile(path, []byte(code), 0644))
		negativeExe := filepath.Join(h.dst, "lifecycle-negative-"+kind+".exe")
		h.run("windows-lifecycle-negative-"+kind+"-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
		out, err := h.command("windows-lifecycle-negative-"+kind+"-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
		check(err != nil && strings.Contains(string(out), "Windows lifecycle") && !strings.Contains(string(out), "PASS:"), "Windows %s negative control failed: %v %s", kind, err, out)
	}
	check(digest(archive) == archiveHash, "lifecycle input archive changed")
	if h.windowsDriver == "clang" || h.windowsDriver == "mingw" {
		h.windowsWeakOptional(arch)
		h.windowsPrimitiveException(arch, cxxRuntime)
	}
	h.results["windows_lifecycle"] = map[string]any{"archive_sha256": archiveHash, "cxx_runtime": cxxRuntime, "threads": 8, "tls_destructors": 9, "static_exit_order": 621345, "negative_controls": []string{"C initialization", "caller TLS cleanup", "static shutdown", "native unwind metadata"}, "shutdown": "explicit, quiescent and idempotent"}
	h.windowsCOMDAT(arch, cxxRuntime)
}

func (h *harness) windowsPrimitiveException(arch, cxxRuntime string) {
	obj := filepath.Join(h.dst, "primitive-exception.obj")
	h.run("windows-primitive-exception-compile.log", h.root, nil, h.windowsCompile(h.windowsCXX, filepath.Join(h.root, "examples/windows_runtime/primitive_exception.cpp"), obj, arch, true)...)
	app := filepath.Join(h.dst, "primitive-exception")
	require(os.Mkdir(app, 0755))
	manifest := filepath.Join(h.dst, "primitive-signatures.json")
	require(os.WriteFile(manifest, []byte(`{"schema":1,"abi":"c","functions":[{"name":"Run","symbol":"bao_windows_primitive_exception_run","params":[],"result":"uint64"}]}`), 0644))
	producer := h.staticWindowsBuildArgs([]string{h.bao, "build", "-target", h.target, "-windows-cxx-runtime", cxxRuntime, "-bindings", manifest, "-symbol", "bao_windows_primitive_exception_run", "-o", filepath.Join(app, "native")})
	h.run("windows-primitive-exception-producer.log", h.root, nil, append(producer, obj)...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-primitive-check\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte("package main\nimport(\"fmt\";\"bao-primitive-check/native\")\nfunc main(){if native.Run()!=42{panic(\"primitive exception\")};fmt.Println(\"PASS: Windows fundamental exception RTTI\")}\n"), 0644))
	exe := filepath.Join(h.dst, "primitive-exception.exe")
	h.run("windows-primitive-exception-build.log", app, h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch}), h.goTool, "build", "-o", exe, ".")
	checkWindowsFunctionTable(exe, arch)
	out := h.run("windows-primitive-exception-run.log", h.root, nil, h.windowsExecute(exe)...)
	check(strings.Contains(string(out), "PASS: Windows fundamental exception RTTI"), "primitive C++ exception failed")
	h.results["windows_fundamental_exception"] = "real int throw/catch with matching native runtime RTTI"
}

func (h *harness) windowsWeakOptional(arch string) {
	objects := []string{}
	for _, name := range []string{"weak_optional", "weak_override"} {
		obj := filepath.Join(h.dst, name+".obj")
		h.run("windows-"+name+"-compile.log", h.root, nil, h.windowsCompile(h.windowsCC, filepath.Join(h.root, "examples/windows_runtime", name+".c"), obj, arch, false)...)
		objects = append(objects, obj)
	}
	signatures := filepath.Join(h.dst, "weak-signatures.json")
	require(os.WriteFile(signatures, []byte(`{"schema":1,"abi":"c","functions":[{"name":"Run","symbol":"bao_windows_optional_run","params":[],"result":"uint64"}]}`), 0644))
	for _, strong := range []bool{false, true} {
		name := "missing"
		want := 42
		members := objects[:1]
		if strong {
			name = "override"
			want = 7
			members = objects
		}
		archive := filepath.Join(h.dst, "weak-"+name+".a")
		h.run("windows-weak-"+name+"-archive.log", h.root, nil, append([]string{h.windowsAR, "rcS", archive}, members...)...)
		app := filepath.Join(h.dst, "weak-"+name)
		require(os.Mkdir(app, 0755))
		args := []string{h.bao, "build", "-target", h.target, "-bindings", signatures, "-symbol", "bao_windows_optional_run", "-o", filepath.Join(app, "native")}
		if strong {
			args = append(args, "-symbol", "bao_windows_missing")
		}
		args = append(args, archive)
		h.run("windows-weak-"+name+"-producer.log", h.root, nil, args...)
		require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-weak-check\ngo 1.26.0\n"), 0644))
		code := fmt.Sprintf("package main\nimport(\"fmt\";\"bao-weak-check/native\")\nfunc main(){if native.Run()!=%d{panic(\"Windows weak %s\")};fmt.Println(\"PASS: Windows weak %s\")}\n", want, name, name)
		require(os.WriteFile(filepath.Join(app, "main.go"), []byte(code), 0644))
		exe := filepath.Join(h.dst, "weak-"+name+".exe")
		h.run("windows-weak-"+name+"-build.log", app, h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch}), h.goTool, "build", "-o", exe, ".")
		checkWindowsFunctionTable(exe, arch)
		out := h.run("windows-weak-"+name+"-run.log", h.root, nil, h.windowsExecute(exe)...)
		check(strings.Contains(string(out), "PASS: Windows weak "+name), "weak fallback/strong override failed")
	}
	h.results["windows_null_weak"] = "real compiler null fallback returned 42; selected strong definition returned 7"
}

// Wine can appear to tolerate an unsorted table for some code layouts. Verify
// the actual PE contract independently of whether the runtime example succeeds.
func checkWindowsFunctionTable(exe, arch string) {
	if arch != "amd64" {
		return
	}
	f, err := pe.NewFile(bytes.NewReader(read(exe)))
	require(err)
	defer f.Close()
	header, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	check(ok, "Windows PE32+ header missing")
	dir := header.DataDirectory[3]
	check(dir.Size > 0 && dir.Size%12 == 0, "invalid Windows PE exception directory")
	for _, sec := range f.Sections {
		if dir.VirtualAddress >= sec.VirtualAddress && uint64(dir.VirtualAddress)+uint64(dir.Size) <= uint64(sec.VirtualAddress)+uint64(sec.Size) {
			data, err := sec.Data()
			require(err)
			offset := dir.VirtualAddress - sec.VirtualAddress
			table := data[offset : offset+dir.Size]
			previous := uint32(0)
			for off := 0; off < len(table); off += 12 {
				begin := binary.LittleEndian.Uint32(table[off:])
				end := binary.LittleEndian.Uint32(table[off+4:])
				check(begin >= previous && end > begin, "unsorted/invalid Windows PE function record %d: %#x..%#x after %#x", off/12, begin, end, previous)
				previous = begin
			}
			return
		}
	}
	check(false, "Windows PE exception directory outside sections")
}

func disableWindowsUnwind(app, arch string) {
	if arch == "arm64" {
		path := filepath.Join(app, "native/symbols_windows_arm64.go")
		code := string(read(path))
		check(strings.Contains(code, "registerFunctionTable(unwindAddress"), "missing native unwind registration")
		code = strings.ReplaceAll(code, "registerFunctionTable(unwindAddress", "registerFunctionTable=func(uintptr,uintptr,uintptr){};registerFunctionTable(unwindAddress")
		require(os.WriteFile(path, []byte(code), 0644))
		return
	}
	entries, err := os.ReadDir(filepath.Join(app, "native"))
	require(err)
	changed := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".syso") {
			path := filepath.Join(app, "native", entry.Name())
			data := read(path)
			for si := 0; si < int(binary.LittleEndian.Uint16(data[2:])); si++ {
				header := data[20+40*si : 20+40*(si+1)]
				if strings.TrimRight(string(header[:8]), "\x00") == ".pdata" {
					copy(header[:8], []byte(".bao.pd\x00"))
					changed++
				}
			}
			require(os.WriteFile(path, data, 0644))
		}
	}
	check(changed > 0, "no PE native exception tables to disable")
}

const windowsLifecycleConsumer = `package main
import("fmt";"runtime";"bao-windows-lifecycle/native")
func main(){
 runtime.LockOSThread()
 if native.Events()!=10{panic("Windows lifecycle process attach")}
 if native.Weak()!=42{panic("Windows lifecycle weak fallback")}
 if native.Exceptions()!=42{panic("Windows lifecycle C++ exceptions/RAII/unwind")}
 if native.Run()!=42{panic("Windows lifecycle C initialization/constructors/TLS/threads")}
 if native.AlignedAddress()%128!=0{panic("Windows lifecycle actual native TLS alignment")}
 if native.Drops()!=8||native.Detaches()!=8||native.TLSLiveBlocks()!=1||native.TLSDestroyedBlocks()!=8{panic("Windows lifecycle native TLS teardown")}
 native.TLSFinalizeCurrentThread()
 if native.Drops()!=9||native.Detaches()!=9||native.TLSLiveBlocks()!=0||native.TLSDestroyedBlocks()!=9{panic("Windows lifecycle caller TLS teardown")}
 native.Shutdown();native.Shutdown()
 if native.State()!=621345||native.Drops()!=9||native.Events()!=11{panic("Windows lifecycle static/atexit/CRT terminator/process detach ordering")}
 fmt.Println("PASS: Windows lifecycle CRT initialization/allocation; C++ throw/catch/rethrow/RAII; eight native threads/nine TLS destructors; static finalization/atexit/terminators; weak fallback")
}
`
