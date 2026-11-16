package main

import (
	"os"
	"path/filepath"
	"strings"
)

// windowsDLL links testdata/windows_dll.cpp into a DLL with the selected
// compiler, translates the DLL and runs a Go consumer that loads it. Negative
// controls drop the DLL's function table and its TLS array patches.
func (h *harness) windowsDLL(arch string) {
	dll := filepath.Join(h.dst, "fixture.dll")
	source := filepath.Join(h.root, "testdata/windows_dll.cpp")
	var args []string
	switch h.windowsDriver {
	case "msvc":
		args = []string{h.windowsCXX, "/nologo", "/LD", "/MD", "/O2", "/EHsc", "/std:c++17", source, "/Fe" + dll, "/Fo" + filepath.Join(h.dst, "windows_dll.obj")}
	case "clang", "mingw":
		// Static C++ runtimes keep the fixture's dependencies to system DLLs.
		args = []string{h.windowsCXX, "-shared", "-O2", "-std=c++17", "-static", "-o", dll, source}
	default:
		return
	}
	h.run("windows-dll-link.log", h.dst, nil, args...)
	app := filepath.Join(h.dst, "dll")
	require(os.Mkdir(app, 0755))
	h.run("windows-dll-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-symbol", "dll_threads", "-o", filepath.Join(app, "native"), dll)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-dll-check\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsDLLConsumer), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
	exe := filepath.Join(h.dst, "dll.exe")
	h.run("windows-dll-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out, err := h.command("windows-dll-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
		check(err == nil && strings.Contains(string(out), "PASS: Windows DLL"), "Windows DLL consumer failed: %v\n%s", err, out)
	}
	manifest := string(read(filepath.Join(app, "native", "bao-manifest.json")))
	controls := map[string][2]string{"unwind": {"registerFunctionTable(base+", "_ = base\n//"}}
	if !strings.Contains(manifest, `"tls_array_loads_patched": 0`) {
		controls["tls"] = [2]string{"copy(image[t.site:], t.code)", "_ = t.site"}
	}
	for kind, edit := range controls {
		negative := filepath.Join(h.dst, "dll-negative-"+kind)
		copyTree(app, negative)
		path := filepath.Join(negative, "native", "symbols_windows_"+arch+".go")
		code := string(read(path))
		check(strings.Contains(code, edit[0]), "no DLL %s step to disable", kind)
		require(os.WriteFile(path, []byte(strings.Replace(code, edit[0], edit[1], 1)), 0644))
		negativeExe := filepath.Join(h.dst, "dll-negative-"+kind+".exe")
		h.run("windows-dll-negative-"+kind+"-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
		out, err := h.command("windows-dll-negative-"+kind+"-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
		check(err != nil || !strings.Contains(string(out), "PASS:"), "Windows DLL %s control did not fail: %s", kind, out)
	}
	h.results["windows_dll"] = map[string]any{"driver": h.windowsDriver, "status": "CHECKED_WITH_LIMITATIONS", "checks": "DllMain, static construction, thread_local across 8 threads, C++ throw/catch inside the DLL, CRT/Win32 imports, exported data; negative controls drop the function table and TLS patches"}
	h.windowsDLLAttached(arch, dll)
}

// windowsDLLAttached combines testdata/windows_dll_glue.c with the DLL that
// windowsDLL linked, wrapping CreateThread in both. Negative controls drop
// the wrapped DLL imports and the glue's imports of the DLL's exports.
func (h *harness) windowsDLLAttached(arch, dll string) {
	glue := filepath.Join(h.dst, "windows_dll_glue.obj")
	h.run("windows-dll-glue-compile.log", h.dst, nil, h.windowsCompile(h.windowsCC, filepath.Join(h.root, "testdata/windows_dll_glue.c"), glue, arch, false)...)
	app := filepath.Join(h.dst, "dll-attached")
	require(os.Mkdir(app, 0755))
	h.run("windows-dll-attached-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-windows-dll", dll, "-wrap", "CreateThread", "-symbol", "glue_check", "-o", filepath.Join(app, "native"), glue)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-dll-attached-check\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsDLLAttachedConsumer), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
	exe := filepath.Join(h.dst, "dll-attached.exe")
	h.run("windows-dll-attached-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out, err := h.command("windows-dll-attached-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
		check(err == nil && strings.Contains(string(out), "PASS: Windows DLL with object"), "Windows DLL with object failed: %v\n%s", err, out)
	}
	for kind, edit := range map[string][2]string{
		"wrap":     {"if im.wrap >= 0 {", "if im.wrap >= 0 && false {"},
		"embedded": {`if functionImports[i].dll == "" {`, `if functionImports[i].dll == "" && false {`},
	} {
		negative := filepath.Join(h.dst, "dll-attached-negative-"+kind)
		copyTree(app, negative)
		path := filepath.Join(negative, "native", "symbols_windows_"+arch+".go")
		code := string(read(path))
		check(strings.Contains(code, edit[0]), "no attached DLL %s step to disable", kind)
		require(os.WriteFile(path, []byte(strings.Replace(code, edit[0], edit[1], 1)), 0644))
		negativeExe := filepath.Join(h.dst, "dll-attached-negative-"+kind+".exe")
		h.run("windows-dll-attached-negative-"+kind+"-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
		out, err := h.command("windows-dll-attached-negative-"+kind+"-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
		check(err != nil || !strings.Contains(string(out), "PASS:"), "Windows DLL with object %s control did not fail: %s", kind, out)
	}
	h.results["windows_dll_attached"] = map[string]any{"driver": h.windowsDriver, "status": "CHECKED_WITH_LIMITATIONS", "checks": "relocatable glue calling a DLL export and reading its data export through embedded-DLL imports, CreateThread wrapped in the glue and in the DLL's imports, glue thread-local variables (zero-fill and initialized) after the DLL's; negative controls drop the wrapped imports and the embedded-DLL import fill"}
}

const windowsDLLAttachedConsumer = `package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"bao-dll-attached-check/native"
)

func main() {
	runtime.LockOSThread()
	var out [5]int32
	syscall.SyscallN(native.SymbolAddr0(), 8, uintptr(unsafe.Pointer(&out[0])))
	_, exported := native.SharedObjectExport("dll_threads")
	got := fmt.Sprint(out, exported)
	fmt.Println("attached:", got)
	if got != "[85 9 14 16 7] true" {
		os.Exit(1)
	}
	native.Shutdown()
	fmt.Println("PASS: Windows DLL with object")
}
`

const windowsDLLConsumer = `package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"bao-dll-check/native"
)

func call(name string, args ...uintptr) int32 {
	address, ok := native.SharedObjectExport(name)
	if !ok {
		panic("missing DLL export " + name)
	}
	r, _, _ := syscall.SyscallN(address, args...)
	return int32(r)
}

func main() {
	// Shutdown requires that only this thread holds the DLL's TLS; unlocked,
	// Go may run each call on a different OS thread.
	runtime.LockOSThread()
	buf := make([]byte, 16)
	ok := call("dll_format", uintptr(unsafe.Pointer(&buf[0])), 16)
	value, _ := native.SharedObjectExport("dll_value")
	threads, _, _ := syscall.SyscallN(native.SymbolAddr0(), 8)
	got := fmt.Sprintf("threads=%d throw=%d state=%d format=%s ok=%d value=%d", int32(threads), call("dll_throw", 1), call("dll_state"), string(buf[:2]), ok, *(*int32)(unsafe.Pointer(value)))
	fmt.Println(got)
	if got != "threads=85 throw=17 state=142 format=v7 ok=1 value=7" {
		fmt.Println("native Windows DLL result")
		os.Exit(1)
	}
	native.Shutdown()
	fmt.Println("PASS: Windows DLL")
}
`
