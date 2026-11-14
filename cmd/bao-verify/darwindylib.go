package main

import (
	"os"
	"path/filepath"
	"strings"
)

// darwinDylib links testdata/darwin_dylib.cpp into a dylib, translates it
// and runs a Go consumer that loads it. Negative controls drop the FDE
// registration and the TLV descriptor setup.
func (h *harness) darwinDylib(arch, sdk string) {
	ldarch := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[arch]
	dylib := filepath.Join(h.dst, "fixture.dylib")
	// libdep is found through @rpath; the first rpath does not exist, and the
	// second names the consumer's directory, where libdep sits.
	h.run("dylib-dep-link.log", h.dst, nil, "xcrun", "clang", "-dynamiclib", "-O2", "-arch", ldarch, "-install_name", "@rpath/libdep.dylib", "-o", filepath.Join(h.dst, "libdep.dylib"), filepath.Join(h.root, "testdata/darwin_dylib_dep.c"))
	h.run("dylib-link.log", h.dst, nil, "xcrun", "clang++", "-dynamiclib", "-O2", "-std=c++17", "-arch", ldarch, "-lz", "-L"+h.dst, "-ldep", "-Wl,-rpath,@loader_path/missing", "-Wl,-rpath,@executable_path", "-o", dylib, filepath.Join(h.root, "testdata/darwin_dylib.cpp"))
	app := filepath.Join(h.dst, "dylib")
	require(os.Mkdir(app, 0o755))
	h.run("dylib-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-sdk", sdk, "-symbol", "dylib_threads", "-o", filepath.Join(app, "native"), dylib)
	h.module(app, "bao-dylib-check", "")
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(darwinDylibConsumer), 0o644))
	exe := filepath.Join(h.dst, "dylib-check")
	h.consumer("dylib-build.log", app, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out, err := h.command("dylib-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, exe)
		check(err == nil && strings.Contains(string(out), "PASS: Darwin dylib"), "Darwin dylib consumer failed: %v\n%s", err, out)
	}
	for kind, edit := range map[string][2]string{
		"unwind": {"registerFrame(base + uintptr(f))", "_ = f"},
		"tlv":    {"*word(d), *word(d + 8) = uint64(tlsAddress_thunk()), 0", "_ = d"},
	} {
		negative := filepath.Join(h.dst, "dylib-negative-"+kind)
		copyTree(app, negative)
		path := filepath.Join(negative, "native", "symbols_darwin_"+arch+".go")
		code := string(read(path))
		check(strings.Contains(code, edit[0]), "no dylib %s step to disable", kind)
		require(os.WriteFile(path, []byte(strings.Replace(code, edit[0], edit[1], 1)), 0o644))
		negativeExe := filepath.Join(h.dst, "dylib-negative-"+kind)
		h.consumer("dylib-negative-"+kind+"-build.log", negative, h.goTool, "build", "-o", negativeExe, ".")
		out, err := h.command("dylib-negative-"+kind+"-run.log", h.root, nil, negativeExe)
		check(err != nil || !strings.Contains(string(out), "PASS:"), "Darwin dylib %s control did not fail: %s", kind, out)
	}
	h.results["darwin_dylib"] = map[string]any{"status": "CHECKED_WITH_LIMITATIONS", "checks": "initializer, static construction, thread_local across 8 threads, C++ throw/catch inside the dylib, libSystem and libz imports bound by library, libdep through @rpath and @executable_path, an address-initialized thread_local, exported data; negative controls drop FDE registration and TLV descriptors"}
}

const darwinDylibConsumer = `package main

import (
	"fmt"
	"os"
	"unsafe"

	"bao-dylib-check/native"
	"github.com/ebitengine/purego"
)

func call(name string, args ...uintptr) int32 {
	address, ok := native.SharedObjectExport(name)
	if !ok {
		panic("missing dylib export " + name)
	}
	r, _, _ := purego.SyscallN(address, args...)
	return int32(r)
}

func main() {
	buf := make([]byte, 16)
	ok := call("dylib_format", uintptr(unsafe.Pointer(&buf[0])), 16)
	value, _ := native.SharedObjectExport("dylib_value")
	threads, _, _ := purego.SyscallN(native.SymbolAddr0(), 8)
	got := fmt.Sprintf("threads=%d throw=%d state=%d format=%s ok=%d value=%d", int32(threads), call("dylib_throw", 1), call("dylib_state"), string(buf[:2]), ok, *(*int32)(unsafe.Pointer(value)))
	fmt.Println(got)
	if got != "threads=85 throw=17 state=142 format=v7 ok=1 value=7" {
		fmt.Println("native Darwin dylib result")
		os.Exit(1)
	}
	fmt.Println("PASS: Darwin dylib")
}
`

// darwinDylibObjC links testdata/darwin_dylib_objc.m and checks the
// Objective-C registration; the negative control skips it.
func (h *harness) darwinDylibObjC(arch, sdk string) {
	ldarch := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[arch]
	dylib := filepath.Join(h.dst, "objc.dylib")
	h.run("dylib-objc-link.log", h.dst, nil, "xcrun", "clang", "-dynamiclib", "-fobjc-arc", "-O2", "-arch", ldarch, "-framework", "Foundation", "-o", dylib, filepath.Join(h.root, "testdata/darwin_dylib_objc.m"))
	app := filepath.Join(h.dst, "dylib-objc")
	require(os.Mkdir(app, 0o755))
	h.run("dylib-objc-producer.log", h.root, nil, h.bao, "build", "-target", h.target, "-sdk", sdk, "-symbol", "objc_check", "-o", filepath.Join(app, "native"), dylib)
	h.module(app, "bao-dylib-objc-check", "")
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(darwinDylibObjCConsumer), 0o644))
	exe := filepath.Join(h.dst, "dylib-objc-check")
	h.consumer("dylib-objc-build.log", app, h.goTool, "build", "-o", exe, ".")
	out, err := h.command("dylib-objc-run.log", h.root, nil, exe)
	check(err == nil && strings.Contains(string(out), "PASS: Objective-C dylib"), "Objective-C dylib consumer failed: %v\n%s", err, out)
	negative := filepath.Join(h.dst, "dylib-objc-negative")
	copyTree(app, negative)
	path := filepath.Join(negative, "native", "symbols_darwin_"+arch+".go")
	code := string(read(path))
	edit := "dylibObjCRegister(base, dylibObjC)"
	check(strings.Contains(code, edit), "no Objective-C registration to disable")
	require(os.WriteFile(path, []byte(strings.Replace(code, edit, "_ = dylibObjC", 1)), 0o644))
	negativeExe := filepath.Join(h.dst, "dylib-objc-negative")
	h.consumer("dylib-objc-negative-build.log", negative, h.goTool, "build", "-o", negativeExe, ".")
	out, err = h.command("dylib-objc-negative-run.log", h.root, nil, negativeExe)
	check(err != nil || !strings.Contains(string(out), "PASS:"), "Objective-C registration control did not fail: %s", out)
	h.results["darwin_dylib_objc"] = map[string]any{"status": "CHECKED_WITH_LIMITATIONS", "checks": "class with protocol, +load in class and category, category methods, subclass via super, category on NSString, NSClassFromString, Foundation; negative control skips registration"}
}

const darwinDylibObjCConsumer = `package main

import (
	"fmt"
	"os"
	"unsafe"

	"bao-dylib-objc-check/native"
	"github.com/ebitengine/purego"
)

func main() {
	var out [7]int32
	purego.SyscallN(native.SymbolAddr0(), uintptr(unsafe.Pointer(&out[0])))
	got := fmt.Sprint(out)
	fmt.Println("objc:", got)
	if got != "[11 2 101 7 6 1 1]" {
		os.Exit(1)
	}
	fmt.Println("PASS: Objective-C dylib")
}
`
