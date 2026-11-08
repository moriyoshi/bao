package main

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// linuxStatic deliberately distinguishes static language-runtime linking from
// fully static native compiler controls. The current Go/native bootstrap still
// requires the glibc loader, pthreads and dynamic symbol lookup.
func (h *harness) linuxStatic() {
	arch := strings.TrimPrefix(h.target, "linux/")
	triple, rustTarget, qemu := "", "aarch64-unknown-linux-gnu", ""
	switch arch {
	case "arm64":
	case "amd64":
		triple, rustTarget, qemu = "x86_64-linux-gnu", "x86_64-unknown-linux-gnu", "qemu-x86_64"
	case "loong64":
		triple, rustTarget, qemu = "loongarch64-linux-gnu", "loongarch64-unknown-linux-gnu", "qemu-loongarch64"
	case "ppc64le":
		triple, rustTarget, qemu = "powerpc64le-linux-gnu", "powerpc64le-unknown-linux-gnu", "qemu-ppc64le"
	default:
		check(false, "unsupported Linux static target %s", h.target)
	}
	image := strings.TrimSpace(string(h.run("static-image.log", h.root, nil, "docker", "image", "inspect", h.image, "--format", "{{.Id}} {{.Architecture}}")))
	check(strings.HasSuffix(image, " arm64"), "Linux static suite requires the ARM64 image from testdata/toolchains/linux-cross.Dockerfile")
	daemon := strings.TrimSpace(string(h.run("static-docker-info.log", h.root, nil, "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}")))
	// Keep the selected image live during the whole suite; external image cache
	// pruning must not change the compiler/runtime between producer and execution.
	keeper := "bao-" + filepath.Base(h.dst)
	h.run("static-image-hold-create.log", h.root, nil, "docker", "create", "--name", keeper, "--platform", "linux/arm64", "--network", "none", "--entrypoint", "/bin/sleep", h.image, "infinity")
	defer h.command("static-image-hold-remove.log", h.root, nil, "docker", "rm", "-f", keeper)
	h.run("static-image-hold-start.log", h.root, nil, "docker", "start", keeper)
	container := func(readonly bool, script string) []string {
		args := []string{"docker", "run", "--rm", "--pull=never", "--platform", "linux/arm64", "--network", "none"}
		volume := h.dst + ":/work"
		if readonly {
			args = append(args, "--read-only")
			volume += ":ro"
		}
		return append(args, "-v", filepath.Join(h.root, "examples")+":/examples:ro", "-v", filepath.Join(h.root, "testdata")+":/testdata:ro", "-v", volume, "--entrypoint", "/bin/sh", h.image, "-c", script)
	}
	h.linuxProducer("static-bao-build.log")
	prefix, sysroot := "", "/"
	if triple != "" {
		prefix, sysroot = triple+"-", "/usr/"+triple
	}
	cc, cxx, ar := prefix+"gcc", prefix+"g++", prefix+"ar"
	flags := "-O2 -g -fPIC -fno-omit-frame-pointer -pthread"
	if arch == "arm64" {
		flags += " -mtls-dialect=desc -mno-outline-atomics"
	}
	compile := fmt.Sprintf(`set -eu
rustc --version
%s --version | head -1
%sld --version | head -1
%s %s -std=c++20 -c /examples/cpp_linux/runtime.cpp -o /work/cpp.o
%s %s -std=c++20 -c /testdata/linux_static_fini.cpp -o /work/fini.o
%s rcs /work/cpp.a /work/cpp.o /work/fini.o
rustc --target %s --crate-type staticlib --crate-name bao_linux_runtime --edition=2024 -O -g /examples/linux_runtime/src/lib.rs -o /work/rust.a
%s r /work/rust.a /work/fini.o
mkdir /work/notices
cp /usr/share/doc/gcc-14-base/copyright /work/notices/GCC-copyright
cp /usr/share/doc/libstdc++6/copyright /work/notices/libstdcxx-copyright
rustdoc=$(rustc --print sysroot)/share/doc/rust
cp "$rustdoc/COPYRIGHT-library.html" /work/notices/Rust-COPYRIGHT-library.html
for path in "$rustdoc"/licenses/*; do cp "$path" "/work/notices/Rust-license-$(basename "$path")"; done
for n in libstdc++.a libgcc_eh.a libgcc.a; do %s -print-file-name=$n; done > /work/runtime-archives.txt
`, cxx, prefix, cxx, flags, cxx, flags, ar, rustTarget, ar, cxx)
	if qemu != "" {
		compile += qemu + " --version | head -1\n"
	}
	toolchain := string(h.run("static-compile.log", h.root, nil, container(false, compile)...))
	check(strings.Contains(toolchain, "rustc 1.99.1 ") && strings.Contains(toolchain, "14.2.0"), "incorrect static runtime toolchain")
	archives := strings.Fields(string(read(filepath.Join(h.dst, "runtime-archives.txt"))))
	check(len(archives) == 3, "missing static runtime archive paths")
	execute := func(exe, procs string, skip string) []string {
		command := "GOMAXPROCS=" + procs + " CC=/bao-no-cc CXX=/bao-no-cxx RUSTC=/bao-no-rustc "
		if skip != "" {
			command += skip + "=1 "
		}
		if qemu != "" {
			command += qemu + " -L " + sysroot + " "
		}
		return container(true, command+"/work/"+exe)
	}
	// Native compiler controls establish both static runtime and full-static
	// feasibility independently of Bao's producer and Go's native bootstrap.
	native := map[string]any{}
	for _, language := range []string{"rust", "cpp"} {
		for _, mode := range []string{"bundled", "fully-static"} {
			name := "native-" + language + "-" + mode
			linkFlags := "-static-libstdc++ -static-libgcc"
			if mode == "fully-static" {
				linkFlags = "-static"
			}
			command := cxx + " -O2 -std=c++20 -pthread -DBAO_CPP_RUNTIME " + linkFlags + " /examples/cpp/native_control.cpp /examples/cpp_linux/runtime.cpp -o /work/" + name
			marker := "PASS: native C++ control"
			if language == "rust" {
				if mode == "fully-static" {
					// Rust std weakly probes this glibc export. Extract its static
					// implementation so native TLS destructors precede pthread
					// keys, as this fixture's late cleanup contract requires.
					linkFlags += " -Wl,-u,__cxa_thread_atexit_impl"
				}
				command = cc + " -O2 -pthread " + linkFlags + " /testdata/linux_rust_control.c /work/rust.a -ldl -lm -lrt -lutil -o /work/" + name
				marker = "PASS: native Rust control"
			}
			h.run(name+"-build.log", h.root, nil, container(false, command)...)
			out := string(h.run(name+"-run.log", h.root, nil, execute(name, "4", "")...))
			check(strings.Contains(out, marker), "ordinary static compiler control failed")
			audit := staticELFAudit(filepath.Join(h.dst, name), mode == "fully-static")
			native[name] = map[string]any{"status": "PASS", "elf": audit, "link_flags": linkFlags, "sha256": digest(filepath.Join(h.dst, name))}
		}
	}
	consumers := map[string]any{}
	for _, language := range []string{"rust", "cpp"} {
		archive := filepath.Join(h.dst, language+".a")
		archiveHash := digest(archive)
		for _, mode := range []string{"runtime", "dwarf"} {
			name := "static-" + language + "-" + mode
			executable := name + "-executable"
			app := filepath.Join(h.dst, name)
			require(os.Mkdir(app, 0755))
			command := "/work/bao-linux build -target " + h.target + " -sysroot " + sysroot + " -require-static-runtime -o /work/" + name + "/native"
			if mode == "dwarf" {
				command += " -bindings dwarf"
			}
			exports := []string{"bao_example_run", "bao_example_check_finalized", "bao_static_fini_state"}
			if language == "cpp" {
				exports = append(exports, "bao_example_finalize")
			}
			for _, symbol := range exports {
				command += " -symbol " + symbol
			}
			for i, path := range archives {
				if language == "cpp" || i != 0 {
					command += " -link-archive " + path
				}
			}
			notices, err := os.ReadDir(filepath.Join(h.dst, "notices"))
			require(err)
			for _, notice := range notices {
				command += " -link-notice /work/notices/" + notice.Name()
			}
			command += " /work/" + language + ".a"
			h.run(name+"-producer.log", h.root, nil, container(false, command)...)
			for i, notice := range notices {
				check(digest(filepath.Join(app, "native", fmt.Sprintf("bao-linked-license-%d.txt", i))) == digest(filepath.Join(h.dst, "notices", notice.Name())), "linked runtime notice changed or missing")
			}
			manifest := readJSON(filepath.Join(app, "native/bao-manifest.json"))
			check(manifest["local_register_frame"] == "__register_frame", "unwind registration is not bundled")
			check(len(manifest["finalizer_tables"].([]any)) >= 2, "native fini tables were not retained")
			if mode == "runtime" {
				h.module(app, "bao-static-check", "")
			} else {
				require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-static-check\ngo 1.26.0\n"), 0644))
			}
			require(os.WriteFile(filepath.Join(app, "main.go"), []byte(staticLinuxConsumer(language, mode)), 0644))
			env := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
			h.run(name+"-build.log", app, env, h.goTool, "build", "-o", filepath.Join(h.dst, executable), ".")
			deps := string(h.run(name+"-deps.log", app, env, h.goTool, "list", "-deps", "."))
			check(strings.Contains(deps, puregoModule) == (mode == "runtime"), "static binding dependency mismatch")
			audit := staticELFAudit(filepath.Join(h.dst, executable), false)
			for _, procs := range []string{"1", "4"} {
				out := string(h.run(name+"-run-"+procs+".log", h.root, nil, execute(executable, procs, "")...))
				check(strings.Contains(out, "PASS: bundled "+language) && (language != "cpp" || strings.Count(out, "CXX_STATIC_FINALIZERS:321") == 1), "static runtime execution failed")
			}
			for _, skip := range []string{"BAO_SKIP_TLS", "BAO_SKIP_FINI"} {
				out, err := h.command(name+"-negative-"+skip+".log", h.root, nil, execute(executable, "1", skip)...)
				check(err != nil && !strings.Contains(string(out), "PASS:") && strings.Contains(string(out), "static check"), "static lifecycle negative did not detect missing %s", skip)
			}
			// Removing frame registration leaves native bytes unchanged and still
			// links. Throw/catch must fail without the registered native FDEs.
			negative := filepath.Join(h.dst, name+"-no-unwind")
			copyTree(app, negative)
			path := filepath.Join(negative, "native/symbols_linux_"+arch+".go")
			source := string(read(path))
			check(strings.Contains(source, "registerFrame(unwindAddress"), "missing FDE registration to disable")
			source = strings.ReplaceAll(source, "registerFrame(unwindAddress", "func(uintptr){}(unwindAddress")
			source = strings.ReplaceAll(source, "var registerFrame func(uintptr)", "var registerFrame func(uintptr)\n_ = registerFrame")
			require(os.WriteFile(path, []byte(source), 0644))
			negExe := name + "-no-unwind-executable"
			h.run(name+"-no-unwind-build.log", negative, env, h.goTool, "build", "-o", filepath.Join(h.dst, negExe), ".")
			out, err := h.command(name+"-no-unwind-run.log", h.root, nil, execute(negExe, "1", "")...)
			check(err != nil && !strings.Contains(string(out), "PASS:") && (strings.Contains(string(out), "SIGABRT") || strings.Contains(string(out), "terminate") || strings.Contains(string(out), "failed to initiate panic")), "static unwind negative did not abort: %s", out)
			if language == "rust" && mode == "dwarf" {
				// Stock cmd/go cannot externally link this cgo-free native bridge.
				out, err := h.command("bao-full-static-external.log", app, env, h.goTool, "build", "-ldflags=-linkmode=external -extldflags=-static", "-o", filepath.Join(h.dst, "not-produced-static"), ".")
				check(err != nil && strings.Contains(string(out), "requires external (cgo) linking"), "unexpected fully static external result; audit and update the supported profile: %s", out)
				_, statErr := os.Stat(filepath.Join(h.dst, "not-produced-static"))
				check(os.IsNotExist(statErr), "failed static attempt left executable")
				// -extldflags does not make internal linking static. Audit this
				// common misleading invocation, rather than labeling it a pass.
				h.run("bao-full-static-internal.log", app, env, h.goTool, "build", "-ldflags=-linkmode=internal -extldflags=-static", "-o", filepath.Join(h.dst, "still-dynamic"), ".")
				staticELFAudit(filepath.Join(h.dst, "still-dynamic"), false)
			}
			consumers[name] = map[string]any{"status": "PASS", "elf": audit, "archive_sha256": archiveHash, "executable_sha256": digest(filepath.Join(h.dst, executable)), "lifecycle_negatives": "missing caller TLS cleanup and fini arrays rejected", "unwind_negative": "links but aborts without FDE registration"}
		}
		check(digest(archive) == archiveHash, "static producer changed source archive")
	}
	execution := "native ARM64 Linux Docker"
	if qemu != "" {
		execution = "QEMU user-mode " + arch + " in ARM64 Linux Docker (physical target hardware unverified)"
	} else {
		check(daemon == "linux/aarch64" || daemon == "linux/arm64", "ARM64 static suite requires native ARM64 Docker daemon")
	}
	h.results["target"], h.results["execution"], h.results["docker_image"] = h.target, execution, image
	h.results["static_linkage"] = map[string]any{"mode": "static language runtimes with dynamic OS libraries", "consumers": consumers, "native_compiler_controls": native, "bao_fully_static": "UNSUPPORTED: fakecgo/pthread/libc/dynamic lookup bootstrap; external link rejects CGO_ENABLED=0, internal -extldflags=-static remains dynamic", "licenses": "GCC/runtime notices and Rust library copyright/license files copied into generated package", "boundaries": "single native image, glibc profile; no musl/static bootstrap, cross-image unloading or exception propagation across Go frames"}
	fmt.Println("PASS static language runtimes", h.target, "(Bao fully static unsupported)")
}

func staticELFAudit(path string, fullyStatic bool) map[string]any {
	f, err := elf.Open(path)
	require(err)
	defer f.Close()
	needed, err := f.DynString(elf.DT_NEEDED)
	require(err)
	interp := false
	for _, p := range f.Progs {
		interp = interp || p.Type == elf.PT_INTERP
	}
	for _, library := range needed {
		for _, runtime := range []string{"libstdc++", "libgcc_s", "libc++", "libunwind"} {
			check(!strings.Contains(library, runtime), "static language runtime silently fell back to %s in %s", library, path)
		}
		switch library {
		case "libc.so.6", "libpthread.so.0", "libdl.so.2", "libm.so.6", "librt.so.1", "libutil.so.1", "ld64.so.2", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "ld-linux-loongarch-lp64d.so.1":
		default:
			check(false, "unrecognized OS dependency %s in static-runtime fixture %s", library, path)
		}
	}
	if fullyStatic {
		check(len(needed) == 0 && !interp, "native fully-static control still has OS dependencies")
	} else {
		check(len(needed) > 0 && interp, "expected OS-dynamic executable for bounded static-runtime profile")
	}
	return map[string]any{"needed": needed, "interpreter_present": interp, "fully_static": fullyStatic}
}

func staticLinuxConsumer(language, mode string) string {
	imports := `"fmt"; "os"; "runtime"; native "bao-static-check/native"`
	setup := "run, check, state := native.BaoExampleRun, native.BaoExampleCheckFinalized, native.BaoStaticFiniState\n"
	finalize := ""
	if mode == "runtime" {
		imports += `; "github.com/ebitengine/purego"`
		setup = "var run, check, state func() uint64\npurego.RegisterFunc(&run,native.SymbolAddr0());purego.RegisterFunc(&check,native.SymbolAddr1());purego.RegisterFunc(&state,native.SymbolAddr2())\n"
	}
	if language == "cpp" {
		if mode == "runtime" {
			setup += "var finalize func()uint64; purego.RegisterFunc(&finalize,native.SymbolAddr3())\n"
		} else {
			setup += "finalize := native.BaoExampleFinalize\n"
		}
		finalize = `if finalize()!=42 || finalize()!=42 { panic("static check C++ shutdown") }`
	}
	return fmt.Sprintf(`package main
import(%s)
func main(){
runtime.LockOSThread(); defer runtime.UnlockOSThread()
%s
if run()!=42 { panic("static check native result") }
if os.Getenv("BAO_SKIP_TLS")=="" { native.TLSFinalizeCurrentThread() }
if check()!=42 || native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=9 { panic("static check TLS cleanup") }
%s
if state()!=0 { panic("static check early fini") }
if os.Getenv("BAO_SKIP_FINI")=="" { native.FinalizeRuntime();native.FinalizeRuntime() }
if state()!=321 { panic("static check fini priority/reverse/idempotence") }
fmt.Println("PASS: bundled %s; dynamic OS libraries; fini=321")
}
`, imports, setup, finalize, language)
}
