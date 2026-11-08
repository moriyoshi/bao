package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type cppCase struct {
	name, source, control, rejection string
	flags, exports                   []string
	handle                           bool
}

func (h *harness) cpp() {
	check(runtime.GOOS == "darwin" && (h.target == "darwin/arm64" || h.target == "darwin/amd64"), "C++ runtime suite requires macOS arm64/amd64")
	arch := strings.TrimPrefix(h.target, "darwin/")
	clangTarget := "arm64-apple-macos11"
	if arch == "amd64" {
		clangTarget = "x86_64-apple-macos11"
	}
	h.env["GOOS"], h.env["GOARCH"] = "darwin", arch
	h.results["target"] = h.target
	h.results["execution"] = "native " + h.target
	if runtime.GOARCH != arch {
		h.results["execution"] = "Rosetta 2 on macOS/" + runtime.GOARCH
	}
	h.results["clang"] = strings.TrimSpace(string(h.run("cpp-clang-version.log", h.root, nil, "/usr/bin/clang++", "--version")))
	h.results["sdk"] = strings.TrimSpace(string(h.run("cpp-sdk-version.log", h.root, nil, "xcrun", "--show-sdk-version")))
	baseFlags := []string{"-std=c++20", "-target", clangTarget, "-O2", "-g", "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer"}
	metadataError := "compact frame with personality/LSDA"
	if arch == "amd64" {
		metadataError = "duplicate compact relocation"
	}
	run := []string{"bao_example_run"}
	tls := []string{"bao_example_run", "bao_example_check_finalized"}
	statics := []string{"bao_example_run", "bao_example_finalize", "bao_example_static_state"}
	cases := []cppCase{
		{name: "unwind", source: "unwind", exports: run, rejection: metadataError},
		{name: "runtime", source: "runtime", control: "BAO_CPP_RUNTIME", exports: []string{"bao_example_run", "bao_example_check_finalized", "bao_example_finalize"}, rejection: metadataError},
		{name: "tls-unadapted", source: "tls", control: "BAO_CPP_TLS", exports: tls, rejection: "system SDK does not export ___dso_handle"},
		{name: "static-unadapted", source: "static_lifetime", control: "BAO_CPP_STATIC", exports: statics, rejection: "system SDK does not export ___dso_handle"},
		{name: "tls-trivial", source: "tls", control: "BAO_CPP_TLS", exports: tls, flags: []string{"-DBAO_CPP_TRIVIAL_TLS"}},
		{name: "tls-destructors", source: "tls", control: "BAO_CPP_TLS", exports: tls, handle: true},
		{name: "initializers", source: "static_initializers", exports: run},
		{name: "static-explicit", source: "static_lifetime", control: "BAO_CPP_STATIC", exports: statics, handle: true},
	}
	results := map[string]any{}
	for _, tc := range cases {
		fmt.Println("Checking C++", tc.name)
		flags := append(append([]string{}, baseFlags...), tc.flags...)
		obj := filepath.Join(h.dst, tc.name+".o")
		source := filepath.Join(h.root, "examples/cpp", tc.source+".cpp")
		h.run(tc.name+"-compile.log", h.root, nil, append(append([]string{"/usr/bin/clang++"}, flags...), "-c", source, "-o", obj)...)
		objectHash := digest(obj)
		// The native link provides its own CRT DSO handle. Never add our Go-side
		// producer adapter to this independent baseline.
		control := filepath.Join(h.dst, tc.name+"-native-control")
		args := append([]string{"/usr/bin/clang++"}, flags...)
		if tc.control != "" {
			args = append(args, "-D"+tc.control)
		}
		args = append(args, obj, filepath.Join(h.root, "examples/cpp/native_control.cpp"), "-framework", "CoreFoundation", "-o", control)
		h.run(tc.name+"-control-build.log", h.root, nil, args...)
		controlOutput, controlErr := h.command(tc.name+"-control-run.log", h.root, nil, control)
		out := string(controlOutput)
		nativeStatus := "PASS"
		if tc.source == "tls" && controlErr != nil && strings.Contains(out, "CPP_NATIVE_RESULT:128; TLS_FINALIZED:42") {
			nativeStatus = "FAIL: native Darwin TLS allocation is not 128-byte aligned; teardown counters passed"
		} else {
			check(controlErr == nil && strings.Contains(out, "PASS: native C++ control") && !strings.Contains(out, "FAIL:"), "native C++ control failed: %v: %s", controlErr, out)
		}
		if tc.source == "static_lifetime" {
			check(strings.Count(out, "CXX_STATIC_FINALIZERS:321") == 1, "native automatic static destruction failed")
		}
		if tc.name == "initializers" {
			check(strings.Contains(out, "CXX_ATEXIT_RAN"), "native process-exit callback did not run")
		}
		archive := filepath.Join(h.dst, tc.name+".a")
		objects := []string{obj}
		if tc.handle {
			handle := filepath.Join(h.dst, tc.name+"-dso.o")
			h.run(tc.name+"-dso-compile.log", h.root, nil, append(append([]string{"/usr/bin/clang++"}, baseFlags...), "-c", filepath.Join(h.root, "examples/cpp/dso_handle.cpp"), "-o", handle)...)
			objects = append(objects, handle)
		}
		h.run(tc.name+"-archive.log", h.root, nil, append([]string{"/usr/bin/ar", "rcs", archive}, objects...)...)
		entry := map[string]any{"source_sha256": digest(source), "object_sha256": objectHash, "producer_flags": flags, "private_dso_handle": tc.handle, "native_control": nativeStatus}
		if tc.rejection != "" {
			output := filepath.Join(h.dst, tc.name+"-rejected-package")
			args := []string{h.bao, "build", "-target", h.target, "-bindings", "dwarf", "-o", output}
			for _, symbol := range tc.exports {
				args = append(args, "-symbol", symbol)
			}
			out, err := h.command(tc.name+"-rejection.log", h.root, nil, append(args, archive)...)
			check(err != nil && strings.Contains(string(out), tc.rejection), "C++ %s: expected explicit boundary %q, got %v: %s", tc.name, tc.rejection, err, out)
			_, err = os.Stat(output)
			check(os.IsNotExist(err), "unsupported C++ case published a package")
			entry["status"], entry["boundary"] = "UNSUPPORTED", tc.rejection
		} else {
			modes := map[string]any{}
			for _, mode := range []string{"runtime", "dwarf"} {
				modes[mode] = h.cppConsumer(tc, archive, mode, arch)
			}
			entry["status"], entry["modes"] = "PASS", modes
		}
		check(digest(obj) == objectHash, "producer modified original C++ debug object")
		results[tc.name] = entry
	}
	h.results["cpp_runtime"] = results
	h.results["status"] = "CHECKED_WITH_LIMITATIONS"
	h.results["unsupported"] = "default C++ exception/cleanup compact augmentation; missing native-linker DSO handle; automatic finalization at Go process exit"
}

func (h *harness) cppConsumer(tc cppCase, archive, mode, arch string) map[string]any {
	prefix := "cpp-" + tc.name + "-" + mode
	app := filepath.Join(h.dst, prefix)
	require(os.Mkdir(app, 0755))
	args := []string{h.bao, "build", "-target", h.target, "-o", filepath.Join(app, "native")}
	if mode == "dwarf" {
		args = append(args, "-bindings", "dwarf")
	}
	for _, symbol := range tc.exports {
		args = append(args, "-symbol", symbol)
	}
	h.run(prefix+"-producer.log", h.root, nil, append(args, archive)...)
	if mode == "runtime" {
		h.module(app, "bao-cpp-check", "")
	} else {
		require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-cpp-check\ngo 1.26.0\n"), 0644))
	}
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(cppConsumerSource(tc, mode)), 0644))
	exe := filepath.Join(h.dst, prefix+"-executable")
	h.consumer(prefix+"-build.log", app, h.goTool, "build", "-o", exe, ".")
	info := string(h.run(prefix+"-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0"), "C++ consumer requires cgo disabled")
	deps := string(h.consumer(prefix+"-deps.log", app, h.goTool, "list", "-deps", "."))
	check(strings.Contains(deps, puregoModule) == (mode == "runtime"), "C++ consumer binding mode dependency mismatch")
	for _, procs := range []string{"1", "4"} {
		out := string(h.run(prefix+"-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe))
		check(strings.Contains(out, "PASS: C++ "+tc.name) && !strings.Contains(out, "CXX_ATEXIT_RAN") && !strings.Contains(out, "CXX_STATIC_FINALIZERS"), "Go exit unexpectedly ran process finalizers: %s", out)
	}
	if tc.name == "static-explicit" {
		out := string(h.run(prefix+"-finalize.log", app, nil, exe, "finalize"))
		check(strings.Count(out, "CXX_STATIC_FINALIZERS:321") == 1 && strings.Contains(out, "PASS:"), "C++ finalization was missing, reordered or repeated: %s", out)
		negativeOut, err := h.command(prefix+"-negative-finalize.log", app, map[string]string{"BAO_CPP_SKIP_STATIC_FINALIZE": "1"}, exe, "finalize")
		check(err != nil && strings.Contains(string(negativeOut), "C++ static finalization") && !strings.Contains(string(negativeOut), "PASS:"), "missing static finalization was not detected")
	}
	if tc.name == "tls-destructors" {
		out, err := h.command(prefix+"-negative-tls.log", app, map[string]string{"BAO_CPP_SKIP_TLS_FINALIZE": "1"}, exe)
		check(err != nil && strings.Contains(string(out), "C++ TLS teardown") && !strings.Contains(string(out), "PASS:"), "missing C++ TLS finalization was not detected")
	}
	if tc.name == "initializers" && mode == "runtime" {
		negative := filepath.Join(h.dst, prefix+"-no-constructors")
		copyTree(app, negative)
		path := filepath.Join(negative, "native/symbols_darwin_"+arch+".go")
		source := string(read(path))
		check(strings.Contains(source, "callConstructor(fn)"), "no C++ initializer calls to disable")
		require(os.WriteFile(path, []byte(strings.ReplaceAll(source, "callConstructor(fn)", "func(uintptr){}(fn)")), 0644))
		negExe := filepath.Join(h.dst, prefix+"-negative-executable")
		h.consumer(prefix+"-negative-build.log", negative, h.goTool, "build", "-o", negExe, ".")
		out, err := h.command(prefix+"-negative-run.log", negative, nil, negExe)
		check(err != nil && strings.Contains(string(out), "C++ native result") && !strings.Contains(string(out), "PASS:"), "missing C++ initialization was not detected")
	}
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-cpp-check", false)
	h.saveJSON(prefix+"-alignment.json", alignment)
	h.run(prefix+"-sign.log", app, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
	h.run(prefix+"-verify.log", app, nil, "codesign", "--verify", "--strict", exe)
	check(strings.Contains(string(h.consumer(prefix+"-signed-run.log", app, exe)), "PASS: C++ "+tc.name), "signed C++ consumer failed")
	if tc.name == "static-explicit" {
		check(strings.Contains(string(h.consumer(prefix+"-signed-finalize.log", app, exe, "finalize")), "CXX_STATIC_FINALIZERS:321"), "signed C++ static finalization failed")
	}
	return map[string]any{"status": "PASS", "alignments_checked": len(alignment), "executable_sha256": digest(exe)}
}

func cppConsumerSource(tc cppCase, mode string) string {
	imports := `"fmt";"os";"runtime";"bao-cpp-check/native"`
	setup := ""
	calls := map[string]string{}
	for i, symbol := range tc.exports {
		name := map[string]string{"bao_example_run": "run", "bao_example_finalize": "finalize", "bao_example_static_state": "state", "bao_example_check_finalized": "checkTLS"}[symbol]
		if mode == "runtime" {
			setup += fmt.Sprintf("var %s func()uint64;purego.RegisterFunc(&%s,native.SymbolAddr%d());", name, name, i)
			calls[symbol] = name + "()"
		} else {
			typed := map[string]string{"bao_example_run": "BaoExampleRun", "bao_example_check_finalized": "BaoExampleCheckFinalized", "bao_example_finalize": "BaoExampleFinalize", "bao_example_static_state": "BaoExampleStaticState"}
			calls[symbol] = "native." + typed[symbol] + "()"
		}
	}
	if mode == "runtime" {
		imports += `;"github.com/ebitengine/purego"`
	}
	body := fmt.Sprintf(`if got:=%s;got!=42{panic(fmt.Sprintf("C++ native result=%%d",got))};`, calls["bao_example_run"])
	if _, ok := calls["bao_example_check_finalized"]; ok {
		body += fmt.Sprintf(`if os.Getenv("BAO_CPP_SKIP_TLS_FINALIZE")==""{native.TLSFinalizeCurrentThread()};if %s!=42||native.TLSLiveBlocks()!=0||native.TLSDestroyedBlocks()!=9{panic("C++ TLS teardown")};`, calls["bao_example_check_finalized"])
	}
	if _, ok := calls["bao_example_static_state"]; ok {
		body += fmt.Sprintf(`if len(os.Args)>1{if os.Getenv("BAO_CPP_SKIP_STATIC_FINALIZE")==""{if %s!=42{panic("C++ static finalization")}};if %s!=43||%s!=42||%s!=43{panic("C++ static finalization")}}else if %s!=42{panic("early static finalization")};`, calls["bao_example_finalize"], calls["bao_example_static_state"], calls["bao_example_finalize"], calls["bao_example_static_state"], calls["bao_example_static_state"])
	}
	return "package main\nimport(" + imports + ")\nvar _=os.Args\nfunc main(){runtime.LockOSThread();defer runtime.UnlockOSThread();" + setup + body + fmt.Sprintf("fmt.Println(%q)}\n", "PASS: C++ "+tc.name+"; "+mode)
}
