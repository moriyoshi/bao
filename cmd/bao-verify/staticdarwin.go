package main

import (
	"debug/macho"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (h *harness) darwinStatic() {
	check(runtime.GOOS == "darwin" && (h.target == "darwin/arm64" || h.target == "darwin/amd64"), "Darwin static verification needs a matching macOS toolchain")
	check(h.staticRuntimeRoot != "", "-static-runtime-root must contain static libc++/unwind libraries and their licenses")
	arch := strings.TrimPrefix(h.target, "darwin/")
	h.env["GOOS"], h.env["GOARCH"] = "darwin", arch
	h.env["RUSTUP_TOOLCHAIN"] = "1.99.1"
	h.results["target"], h.results["execution"] = h.target, "native "+h.target
	if runtime.GOARCH != arch {
		h.results["execution"] = "Rosetta 2 on macOS/" + runtime.GOARCH
	}
	h.results["clang"] = string(h.run("static-clang.log", h.root, nil, "/usr/bin/clang++", "--version"))
	h.results["rust"] = string(h.run("static-rust.log", h.root, nil, "rustc", "--version"))
	cpp := filepath.Join(h.staticRuntimeRoot, "lib/libc++.a")
	unwind := filepath.Join(h.staticRuntimeRoot, "lib/libunwind.a")
	check(len(read(cpp)) > 0 && len(read(unwind)) > 0, "static runtime archives are missing")
	// Rust std/unwinding is a required gate before the C++ static-runtime case.
	h.darwinStaticCase(arch, "rust", filepath.Join(h.root, "examples/rust_runtime"), unwind, nil)
	clangArch := "arm64"
	if arch == "amd64" {
		clangArch = "x86_64"
	}
	objects := []string{}
	for i, source := range []string{"examples/static_runtime/darwin.cpp", "examples/cpp/dso_handle.cpp"} {
		obj := filepath.Join(h.dst, fmt.Sprintf("static-cpp-%d.o", i))
		h.run(fmt.Sprintf("static-cpp-%d-compile.log", i), h.root, nil, "/usr/bin/clang++", "-target", clangArch+"-apple-macos11", "-std=c++20", "-O2", "-g", "-fno-exceptions", "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer", "-nostdinc++", "-I"+filepath.Join(h.staticRuntimeRoot, "include/c++/v1"), "-c", filepath.Join(h.root, source), "-o", obj)
		objects = append(objects, obj)
	}
	archive := filepath.Join(h.dst, "static-cpp.a")
	h.run("static-cpp-archive.log", h.root, nil, append([]string{"/usr/bin/ar", "rcs", archive}, objects...)...)
	h.darwinStaticCase(arch, "cpp", archive, cpp, nil)
	h.results["fully_static"] = map[string]any{"status": "UNSUPPORTED", "reason": "stock Go and the supported macOS SDK require dynamic OS libraries including libSystem"}
}

func (h *harness) darwinStaticCase(arch, name, input, archive string, extra []string) {
	app := filepath.Join(h.dst, "static-"+name)
	require(os.Mkdir(app, 0755))
	functions := []map[string]any{}
	for _, f := range []struct{ goName, symbol string }{{"Run", "bao_example_run"}, {"Check", "bao_example_check_finalized"}} {
		if name == "cpp" {
			if f.goName == "Run" {
				f.symbol = "bao_static_run"
			} else {
				f.symbol = "bao_static_check"
			}
		}
		functions = append(functions, map[string]any{"name": f.goName, "symbol": f.symbol, "params": []string{}, "result": "uint64"})
	}
	if name == "cpp" {
		functions = append(functions, map[string]any{"name": "Finalize", "symbol": "bao_static_finalize", "params": []string{}, "result": "uint64"})
		functions = append(functions, map[string]any{"name": "Finalized", "symbol": "bao_static_finalized", "params": []string{}, "result": "uint64"})
	}
	manifest := filepath.Join(h.dst, "static-"+name+"-signatures.json")
	b, err := json.Marshal(map[string]any{"schema": 1, "abi": "c", "functions": functions})
	require(err)
	require(os.WriteFile(manifest, b, 0644))
	args := []string{h.bao, "build", "-target", h.target, "-bindings", manifest, "-link-archive", archive, "-require-static-runtime", "-o", filepath.Join(app, "native")}
	for _, f := range functions {
		args = append(args, "-symbol", f["symbol"].(string))
	}
	var notices []string
	for _, p := range []string{"libcxx/LICENSE.TXT", "libcxxabi/LICENSE.TXT", "libunwind/LICENSE.TXT"} {
		path := filepath.Join(h.staticRuntimeRoot, p)
		if _, err := os.Stat(path); err == nil {
			notices = append(notices, path)
		}
	}
	check(len(notices) == 3, "all three LLVM runtime license files are required under -static-runtime-root")
	if name == "rust" {
		sysroot := strings.TrimSpace(string(h.run("static-rust-sysroot.log", h.root, nil, "rustc", "--print", "sysroot")))
		doc := filepath.Join(sysroot, "share/doc/rust")
		notices = append(notices, filepath.Join(doc, "COPYRIGHT-library.html"))
		entries, err := os.ReadDir(filepath.Join(doc, "licenses"))
		require(err)
		check(len(entries) > 0, "Rust runtime license files are missing")
		for _, entry := range entries {
			if !entry.IsDir() {
				notices = append(notices, filepath.Join(doc, "licenses", entry.Name()))
			}
		}
	}
	for _, notice := range notices {
		args = append(args, "-link-notice", notice)
	}
	args = append(args, extra...)
	h.run("static-"+name+"-producer.log", h.root, nil, append(args, input)...)
	for i, notice := range notices {
		check(digest(notice) == digest(filepath.Join(app, "native", fmt.Sprintf("bao-linked-license-%d.txt", i))), "linked runtime license was changed or omitted")
	}
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-static-darwin\ngo 1.26.0\n"), 0644))
	finalize := ""
	if name == "cpp" {
		finalize = `if native.Finalize()!=42 || native.Finalize()!=42 || native.Finalized()!=42 {panic("static C++ finalizers")}`
	}
	source := `package main
import("fmt";"runtime";native "bao-static-darwin/native")
func main(){runtime.LockOSThread();if native.Run()!=42 {panic("static native run")};native.TLSFinalizeCurrentThread();if native.Check()!=42 {panic("static TLS cleanup")};` + finalize + `;fmt.Println("PASS: static Darwin ` + name + `")}
`
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(source), 0644))
	exe := filepath.Join(h.dst, "static-"+name+".exe")
	h.run("static-"+name+"-build.log", app, h.consumerEnv(nil), h.goTool, "build", "-o", exe, ".")
	f, err := macho.Open(exe)
	require(err)
	libs, err := f.ImportedLibraries()
	require(err)
	require(f.Close())
	for _, lib := range libs {
		check(!languageRuntimeLibrary(lib), "static Darwin consumer still imports %s", lib)
	}
	check(len(libs) > 0, "Darwin audit did not find its required OS imports")
	for _, procs := range []string{"1", "4"} {
		out := h.run("static-"+name+"-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, exe)
		check(strings.Contains(string(out), "PASS: static Darwin "+name), "static Darwin execution failed")
	}
	h.run("static-"+name+"-sign.log", h.root, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
	h.run("static-"+name+"-verify-sign.log", h.root, nil, "codesign", "--verify", "--strict", exe)
	check(strings.Contains(string(h.run("static-"+name+"-signed-run.log", h.root, nil, exe)), "PASS:"), "signed static Darwin run failed")
	negatives := []string{"tls"}
	if name == "rust" {
		negatives = append(negatives, "unwind")
	} else {
		negatives = append(negatives, "finalizers")
	}
	for _, kind := range negatives {
		negative := filepath.Join(h.dst, "negative-"+name+"-"+kind)
		copyTree(app, negative)
		path := filepath.Join(negative, "main.go")
		before := string(read(path))
		after, expected := before, "static TLS cleanup"
		switch kind {
		case "tls":
			after = strings.Replace(before, "native.TLSFinalizeCurrentThread();", "", 1)
		case "finalizers":
			after = strings.ReplaceAll(before, "native.Finalize()!=42", "false")
			expected = "static C++ finalizers"
		case "unwind":
			path = filepath.Join(negative, "native/symbols_darwin_"+arch+".go")
			before = string(read(path))
			after = strings.ReplaceAll(before, "registerFrame(", "func(uintptr) {}(")
			after = strings.Replace(after, "var registerFrame func(uintptr)", "var registerFrame func(uintptr)\n_ = registerFrame", 1)
			expected = "failed to initiate panic"
		}
		check(after != before, "static %s negative did not change its control", kind)
		require(os.WriteFile(path, []byte(after), 0644))
		negativeExe := filepath.Join(h.dst, "negative-"+name+"-"+kind+".exe")
		h.run("static-"+name+"-"+kind+"-negative-build.log", negative, nil, h.goTool, "build", "-o", negativeExe, ".")
		out, err := h.command("static-"+name+"-"+kind+"-negative-run.log", negative, nil, negativeExe)
		check(err != nil && strings.Contains(string(out), expected) && !strings.Contains(string(out), "PASS:"), "static %s negative was not detected: %s", kind, out)
	}
	h.results["static_"+name] = map[string]any{"status": "PASS", "runtime_archive_sha256": digest(archive), "executable_sha256": digest(exe), "system_libraries": libs, "license_files": len(notices), "negative_controls": negatives}
}
