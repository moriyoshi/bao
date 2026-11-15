package main

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const cppLinuxArmImage = "gcc@sha256:2bafb163aaa91eef7856f17ff0abf69144ebe3218a4eea75c043bb3043b9ecfa"
const cppLinuxAMDImage = "gcc@sha256:aed16c4791a9932c9588459d126154ec1cde5fcb2fa1cec2912e7f692c783116"

func cppLinuxTriple(arch string) string {
	switch arch {
	case "loong64":
		return "loongarch64-linux-gnu"
	case "ppc64le":
		return "powerpc64le-linux-gnu"
	}
	return ""
}

func cppLinuxSysroot(arch string) string {
	if triple := cppLinuxTriple(arch); triple != "" {
		return "/usr/" + triple
	}
	return "/"
}

func cppLinuxPlatform(arch string) string {
	if cppLinuxTriple(arch) != "" {
		return "linux/arm64"
	}
	return "linux/" + arch
}

func cppLinuxQEMU(arch string) string {
	if arch == "loong64" {
		return "qemu-loongarch64"
	}
	return "qemu-ppc64le"
}

func (h *harness) cppLinux() {
	arch := strings.TrimPrefix(h.target, "linux/")
	check(arch == "arm64" || arch == "amd64" || arch == "loong64" || arch == "ppc64le", "unsupported Linux C++ target %s", h.target)
	check(h.cxx == "g++" || h.cxx == "clang++", "Linux C++ compiler must be g++ or clang++")
	triple := cppLinuxTriple(arch)
	producerArch := strings.TrimPrefix(cppLinuxPlatform(arch), "linux/")
	daemon := strings.TrimSpace(string(h.run("cpp-docker-info.log", h.root, nil, "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}")))
	imageInfo := strings.TrimSpace(string(h.run("cpp-image.log", h.root, nil, "docker", "image", "inspect", h.image, "--format", "{{.Id}} {{.Architecture}}")))
	check(strings.HasSuffix(imageInfo, " "+producerArch), "C++ Docker producer image architecture mismatch: %s", imageInfo)
	execution := "native Linux " + arch + " Docker"
	if !(arch == "arm64" && (daemon == "linux/aarch64" || daemon == "linux/arm64") || arch == "amd64" && (daemon == "linux/x86_64" || daemon == "linux/amd64")) {
		execution = "emulated Linux " + arch + " Docker on " + daemon
	}
	h.results["target"], h.results["execution"] = h.target, execution
	h.results["docker_image"], h.results["docker_daemon"] = imageInfo, daemon
	container := func(readonly bool, command ...string) []string {
		args := []string{"docker", "run", "--rm", "--pull=never", "--platform", cppLinuxPlatform(arch), "--network", "none"}
		if readonly {
			args = append(args, "--read-only")
		}
		args = append(args, "-v", filepath.Join(h.root, "examples")+":/examples:ro", "-v", filepath.Join(h.root, "testdata")+":/testdata:ro", "-v", h.dst+":/work", "--entrypoint", "/bin/sh", h.image, "-c")
		return append(args, command...)
	}
	compilerFlags := "-std=c++20 -O2 -g -fPIC -fno-omit-frame-pointer -pthread"
	compiler, archiveTool, linker := h.cxx, "ar", "ld"
	if triple != "" {
		archiveTool, linker = triple+"-ar", triple+"-ld"
		if h.cxx == "g++" {
			compiler = triple + "-g++"
		}
		h.results["emulator"] = string(h.run("cpp-linux-qemu-version.log", h.root, nil, container(true, cppLinuxQEMU(arch)+" --version | head -1")...))
	}
	if arch == "arm64" {
		compilerFlags += " -mno-outline-atomics"
		if h.cxx == "g++" {
			compilerFlags += " -mtls-dialect=desc"
		}
	} else if arch == "amd64" {
		compilerFlags += " -march=x86-64 -mtune=generic"
	}
	if h.cxx == "clang++" {
		if triple == "" {
			compilerFlags += " --gcc-toolchain=/usr/local -stdlib=libstdc++"
		} else {
			compilerFlags += " --target=" + triple + " --gcc-toolchain=/usr -stdlib=libstdc++"
		}
	}
	toolInfo := string(h.run("cpp-linux-toolchain.log", h.root, nil, container(true, compiler+" --version; "+linker+" --version | head -1; ldd --version | head -1; uname -m")...))
	h.results["cpp_compiler"], h.results["cpp_flags"] = toolInfo, compilerFlags
	producer := filepath.Join(h.dst, "bao-linux")
	selected := false
	if f, err := elf.Open(h.bao); err == nil {
		selected = producerArch == "arm64" && f.Machine == elf.EM_AARCH64 || producerArch == "amd64" && f.Machine == elf.EM_X86_64
		require(f.Close())
	}
	if selected {
		copyFile(h.bao, producer)
		require(os.Chmod(producer, 0755))
	} else {
		h.run("cpp-linux-bao-build.log", h.root, h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": producerArch}), h.goTool, "build", "-o", producer, "./cmd/bao")
	}
	h.results["linux_producer_sha256"], h.results["selected_linux_artifact"] = digest(producer), selected
	h.run("cpp-linux-bao-version.log", h.root, nil, container(true, "/work/bao-linux version -json")...)
	cases := []cppCase{
		{name: "unwind", source: "cpp/unwind", exports: []string{"bao_example_run"}},
		{name: "tls-destructors", source: "cpp/tls", control: "BAO_CPP_TLS", exports: []string{"bao_example_run", "bao_example_check_finalized"}},
		{name: "initializers", source: "cpp/static_initializers", exports: []string{"bao_example_run"}},
		{name: "static-explicit", source: "cpp/static_lifetime", control: "BAO_CPP_STATIC", exports: []string{"bao_example_run", "bao_example_finalize", "bao_example_static_state"}},
		{name: "runtime", source: "cpp_linux/runtime", control: "BAO_CPP_RUNTIME", exports: []string{"bao_example_run", "bao_example_check_finalized", "bao_example_finalize", "bao_example_static_state"}},
	}
	results := map[string]any{}
	for _, tc := range cases {
		fmt.Println("Checking Linux C++", h.cxx, tc.name, h.target)
		controlFlag := ""
		if tc.control != "" {
			controlFlag = " -D" + tc.control
		}
		script := fmt.Sprintf("set -eu\n%s %s -c /examples/%s.cpp -o /work/%s.o\n%s rcs /work/%s.a /work/%s.o\n%s %s%s /work/%s.o /examples/cpp/native_control.cpp -o /work/%s-control\n", compiler, compilerFlags, tc.source, tc.name, archiveTool, tc.name, tc.name, compiler, compilerFlags, controlFlag, tc.name, tc.name)
		h.run(tc.name+"-linux-compile.log", h.root, nil, container(false, script)...)
		out := string(h.run(tc.name+"-linux-control.log", h.root, nil, h.cppLinuxExec(arch, tc.name+"-control", "1", nil)...))
		check(strings.Contains(out, "PASS: native C++ control") && !strings.Contains(out, "FAIL:"), "Linux native C++ control failed: %s", out)
		if tc.name == "initializers" {
			check(strings.Contains(out, "CXX_ATEXIT_RAN"), "Linux native exit callback missing")
		}
		if tc.name == "static-explicit" || tc.name == "runtime" {
			check(strings.Count(out, "CXX_STATIC_FINALIZERS:321") == 1, "Linux native static destruction failed: %s", out)
		}
		archive := filepath.Join(h.dst, tc.name+".a")
		archiveHash := digest(archive)
		entry := map[string]any{"source_sha256": digest(filepath.Join(h.root, "examples", tc.source+".cpp")), "archive_sha256": archiveHash, "native_control": "PASS"}
		modes := map[string]any{}
		for _, mode := range []string{"runtime", "dwarf"} {
			modes[mode] = h.cppLinuxConsumer(tc, mode, arch, container)
		}
		entry["status"], entry["modes"] = "PASS", modes
		check(digest(archive) == archiveHash, "Linux C++ producer changed original archive")
		results[tc.name] = entry
	}
	h.results["cpp_linux"] = results
	diagnostic := "readelf -d /work/runtime-control\nreadelf -d /work/cpp-linux-runtime-dwarf-executable"
	if triple == "" {
		diagnostic = "ldd /work/runtime-control\n" + diagnostic
	}
	h.results["cpp_runtime_libraries"] = string(h.run("cpp-linux-runtime-libraries.log", h.root, nil, container(true, "set -eu\n"+diagnostic)...))
	h.cppLinuxScalars(arch, compiler, compilerFlags, archiveTool, container)
	h.cppLinuxSymbolVersions(arch, compiler, compilerFlags, archiveTool, container)
	h.cppLinuxCommons(arch, compiler, compilerFlags, archiveTool, container)
	h.cppLinuxMissingWeak(arch, compiler, compilerFlags, archiveTool, container)
}

// cppLinuxSymbolVersions checks that imports bind versioned glibc symbols:
// testdata/linux_symbol_versions.c needs pthread_cond_init's default version,
// since x86_64's GLIBC_2.2.5 compatibility one, which an unversioned
// reference binds, rejects a CLOCK_MONOTONIC condattr. The negative control
// removes the versions from the generated directives; on amd64 it must fail.
func (h *harness) cppLinuxSymbolVersions(arch, compiler, compilerFlags, archiveTool string, container func(bool, ...string) []string) {
	flags := strings.Replace(compilerFlags, "-std=c++20", "-std=gnu11 -x c", 1)
	h.run("symbol-versions-compile.log", h.root, nil, container(false, "set -eu\n"+compiler+" "+flags+" -c /testdata/linux_symbol_versions.c -o /work/symbol-versions.o\n"+archiveTool+" rcs /work/symbol-versions.a /work/symbol-versions.o")...)
	app := filepath.Join(h.dst, "symbol-versions")
	require(os.Mkdir(app, 0755))
	h.run("symbol-versions-producer.log", h.root, nil, container(false, "/work/bao-linux build -target "+h.target+" -sysroot "+cppLinuxSysroot(arch)+" -bindings dwarf -symbol bao_condtest -o /work/symbol-versions/native /work/symbol-versions.a")...)
	source := filepath.Join(app, "native/symbols_linux_"+arch+".go")
	directives := map[string]string{}
	for _, line := range strings.Split(string(read(source)), "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[0] == "//go:cgo_import_dynamic" {
			name, version, _ := strings.Cut(f[2], "#")
			directives[name] = version
		}
	}
	check(directives["pthread_cond_init"] != "" && directives["memcpy"] != "", "imports are not versioned: %v", directives)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-symbol-versions\ngo 1.26.0\n"), 0644))
	main := "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\n\t\"bao-symbol-versions/native\"\n)\n\nfunc main() {\n\tr := native.BaoCondtest()\n\tfmt.Println(\"condtest:\", r)\n\tif r != 1 {\n\t\tos.Exit(1)\n\t}\n}\n"
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(main), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	h.run("symbol-versions-build.log", app, cross, h.goTool, "build", "-o", filepath.Join(h.dst, "symbol-versions-executable"), ".")
	out := string(h.run("symbol-versions-run.log", h.root, nil, h.cppLinuxExec(arch, "symbol-versions-executable", "1", nil)...))
	check(strings.Contains(out, "condtest: 1\n"), "versioned imports failed: %s", out)
	negative := filepath.Join(h.dst, "symbol-versions-negative")
	copyTree(app, negative)
	path := filepath.Join(negative, "native/symbols_linux_"+arch+".go")
	var lines []string
	for _, line := range strings.Split(string(read(path)), "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[0] == "//go:cgo_import_dynamic" {
			line = strings.Join([]string{f[0], f[1], strings.SplitN(f[2], "#", 2)[0], f[3]}, " ")
		}
		lines = append(lines, line)
	}
	require(os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644))
	h.run("symbol-versions-negative-build.log", negative, cross, h.goTool, "build", "-o", filepath.Join(h.dst, "symbol-versions-negative-executable"), ".")
	negOut, negErr := h.command("symbol-versions-negative-run.log", h.root, nil, h.cppLinuxExec(arch, "symbol-versions-negative-executable", "1", nil)...)
	unversioned := "passes"
	if negErr != nil || !strings.Contains(string(negOut), "condtest: 1\n") {
		unversioned = "fails: " + strings.TrimSpace(string(negOut))
	}
	if arch == "amd64" {
		check(strings.HasPrefix(unversioned, "fails"), "unversioned imports unexpectedly passed on amd64: %s", negOut)
	}
	h.results["symbol_versions"] = map[string]any{"status": "PASS", "pthread_cond_init": directives["pthread_cond_init"], "memcpy": directives["memcpy"], "imports": len(directives), "unversioned_control": unversioned}
}

// cppLinuxCommons checks that common symbols, which the partial link leaves
// unallocated, are defined zero-filled and aligned: testdata/linux_common.c
// has a hidden assembler .comm and a -fcommon tentative definition.
func (h *harness) cppLinuxCommons(arch, compiler, compilerFlags, archiveTool string, container func(bool, ...string) []string) {
	flags := strings.Replace(compilerFlags, "-std=c++20", "-std=gnu11 -fcommon -x c", 1)
	h.run("common-compile.log", h.root, nil, container(false, "set -eu\n"+compiler+" "+flags+" -c /testdata/linux_common.c -o /work/common.o\n"+archiveTool+" rcs /work/common.a /work/common.o")...)
	app := filepath.Join(h.dst, "common")
	require(os.Mkdir(app, 0755))
	h.run("common-producer.log", h.root, nil, container(false, "/work/bao-linux build -target "+h.target+" -sysroot "+cppLinuxSysroot(arch)+" -bindings dwarf -symbol bao_common -o /work/common/native /work/common.a")...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-common\ngo 1.26.0\n"), 0644))
	main := "package main\n\nimport (\n\t\"fmt\"\n\n\t\"bao-common/native\"\n)\n\nfunc main() {\n\ta, b := native.BaoCommon(), native.BaoCommon()\n\tfmt.Println(\"common:\", a, b)\n}\n"
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(main), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	h.run("common-build.log", app, cross, h.goTool, "build", "-o", filepath.Join(h.dst, "common-executable"), ".")
	out := string(h.run("common-run.log", h.root, nil, h.cppLinuxExec(arch, "common-executable", "1", nil)...))
	check(strings.Contains(out, "common: 173 246\n"), "common symbols failed: %s", out)
	h.results["common_symbols"] = map[string]any{"status": "PASS", "checks": "hidden assembler .comm with 16-byte alignment and a -fcommon tentative definition: zero-initialized, aligned, persistent"}
}

// cppLinuxMissingWeak checks NULL tests of weak symbols that no library
// defines, in the forms zstd's optional trace hooks use: on amd64 GCC emits
// `cmpq $0, sym@GOTPCREL(%rip)`, whose -5 bias was refused. Only amd64 and
// arm64 are checked; the cross-ISA targets keep their own weak profiles.
func (h *harness) cppLinuxMissingWeak(arch, compiler, compilerFlags, archiveTool string, container func(bool, ...string) []string) {
	if arch != "amd64" && arch != "arm64" {
		return
	}
	flags := strings.Replace(compilerFlags, "-std=c++20", "-std=gnu11 -x c", 1)
	h.run("missing-weak-compile.log", h.root, nil, container(false, "set -eu\n"+compiler+" "+flags+" -c /testdata/linux_missing_weak.c -o /work/missing-weak.o\n"+archiveTool+" rcs /work/missing-weak.a /work/missing-weak.o")...)
	app := filepath.Join(h.dst, "missing-weak")
	require(os.Mkdir(app, 0755))
	h.run("missing-weak-producer.log", h.root, nil, container(false, "/work/bao-linux build -target "+h.target+" -sysroot "+cppLinuxSysroot(arch)+" -bindings dwarf -symbol bao_weak -o /work/missing-weak/native /work/missing-weak.a")...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-missing-weak\ngo 1.26.0\n"), 0644))
	main := "package main\n\nimport (\n\t\"fmt\"\n\n\t\"bao-missing-weak/native\"\n)\n\nfunc main() { fmt.Println(\"weak:\", native.BaoWeak()) }\n"
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(main), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	h.run("missing-weak-build.log", app, cross, h.goTool, "build", "-o", filepath.Join(h.dst, "missing-weak-executable"), ".")
	out := string(h.run("missing-weak-run.log", h.root, nil, h.cppLinuxExec(arch, "missing-weak-executable", "1", nil)...))
	check(strings.Contains(out, "weak: 21\n"), "missing weak references failed: %s", out)
	h.results["missing_weak"] = map[string]any{"status": "PASS", "checks": "NULL tests of an undefined weak function and data address, including the amd64 GCC cmpq $0, sym@GOTPCREL(%rip) form"}
}

func (h *harness) cppLinuxExec(arch, executable, procs string, extra map[string]string, args ...string) []string {
	command := []string{"docker", "run", "--rm", "--pull=never", "--platform", cppLinuxPlatform(arch), "--network", "none", "--read-only", "-e", "GOMAXPROCS=" + procs, "-e", "CC=/bao-no-cc", "-e", "CXX=/bao-no-cxx", "-e", "RUSTC=/bao-no-rustc", "-v", h.dst + ":/work:ro"}
	for key, value := range extra {
		command = append(command, "-e", key+"="+value)
	}
	if cppLinuxTriple(arch) != "" {
		command = append(command, "--entrypoint", "/usr/bin/"+cppLinuxQEMU(arch), h.image, "-L", cppLinuxSysroot(arch), "/work/"+executable)
	} else {
		command = append(command, "--entrypoint", "/work/"+executable, h.image)
	}
	return append(command, args...)
}

func (h *harness) cppLinuxConsumer(tc cppCase, mode, arch string, container func(bool, ...string) []string) map[string]any {
	prefix := "cpp-linux-" + tc.name + "-" + mode
	app := filepath.Join(h.dst, prefix)
	require(os.Mkdir(app, 0755))
	command := "/work/bao-linux build -target " + h.target + " -sysroot " + cppLinuxSysroot(arch) + " -o /work/" + prefix + "/native"
	if mode == "dwarf" {
		command += " -bindings dwarf"
	}
	for _, symbol := range tc.exports {
		command += " -symbol " + symbol
	}
	command += " /work/" + tc.name + ".a"
	h.run(prefix+"-producer.log", h.root, nil, container(false, command)...)
	if mode == "runtime" {
		h.module(app, "bao-cpp-check", "")
	} else {
		require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-cpp-check\ngo 1.26.0\n"), 0644))
	}
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(cppConsumerSource(tc, mode)), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	executable := prefix + "-executable"
	exe := filepath.Join(h.dst, executable)
	h.run(prefix+"-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	deps := string(h.run(prefix+"-deps.log", app, cross, h.goTool, "list", "-deps", "."))
	check(strings.Contains(deps, puregoModule) == (mode == "runtime"), "Linux C++ binding dependencies mismatch")
	info := string(h.run(prefix+"-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0"), "Linux C++ consumer must disable cgo")
	for _, procs := range []string{"1", "4"} {
		out := string(h.run(prefix+"-run-"+procs+".log", h.root, nil, h.cppLinuxExec(arch, executable, procs, nil)...))
		check(strings.Contains(out, "PASS: C++ "+tc.name) && !strings.Contains(out, "CXX_ATEXIT_RAN") && !strings.Contains(out, "CXX_STATIC_FINALIZERS"), "Linux Go exit ran native finalizers unexpectedly: %s", out)
		if tc.name == "static-explicit" || tc.name == "runtime" {
			out = string(h.run(prefix+"-finalize-"+procs+".log", h.root, nil, h.cppLinuxExec(arch, executable, procs, nil, "finalize")...))
			check(strings.Count(out, "CXX_STATIC_FINALIZERS:321") == 1 && strings.Contains(out, "PASS:"), "Linux static finalization failed: %s", out)
		}
	}
	negative := func(kind string, extra map[string]string, want string, args ...string) {
		out, err := h.command(prefix+"-negative-"+kind+".log", h.root, nil, h.cppLinuxExec(arch, executable, "1", extra, args...)...)
		check(err != nil && strings.Contains(string(out), want) && !strings.Contains(string(out), "PASS:"), "Linux C++ %s negative control failed: %v: %s", kind, err, out)
	}
	if tc.name == "tls-destructors" || tc.name == "runtime" {
		negative("tls", map[string]string{"BAO_CPP_SKIP_TLS_FINALIZE": "1"}, "C++ TLS teardown")
	}
	if tc.name == "static-explicit" || tc.name == "runtime" {
		negative("static", map[string]string{"BAO_CPP_SKIP_STATIC_FINALIZE": "1"}, "C++ static finalization", "finalize")
	}
	if tc.name == "unwind" || tc.name == "runtime" || tc.name == "initializers" {
		dir := filepath.Join(h.dst, prefix+"-negative")
		copyTree(app, dir)
		path := filepath.Join(dir, "native/symbols_linux_"+arch+".go")
		source := string(read(path))
		kind, want := "unwind", "terminate"
		if tc.name == "initializers" {
			check(strings.Contains(source, "callConstructor("), "missing Linux C++ constructors to disable")
			source = strings.Replace(source, "callConstructor(", "callConstructor = func(uintptr){}\ncallConstructor(", 1)
			kind, want = "constructor", "C++ native result"
		} else {
			check(strings.Contains(source, "registerFrame(unwindAddress"), "missing Linux C++ unwind registration to disable")
			source = strings.Replace(source, "registerFrame(unwindAddress", "registerFrame = func(uintptr){}\nregisterFrame(unwindAddress", 1)
		}
		require(os.WriteFile(path, []byte(source), 0644))
		negExe := executable + "-negative"
		h.run(prefix+"-negative-build.log", dir, cross, h.goTool, "build", "-o", filepath.Join(h.dst, negExe), ".")
		out, err := h.command(prefix+"-negative-"+kind+".log", h.root, nil, h.cppLinuxExec(arch, negExe, "1", nil)...)
		check(err != nil && strings.Contains(string(out), want) && !strings.Contains(string(out), "PASS:"), "Linux C++ %s control failed: %v %s", kind, err, out)
	}
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-cpp-check", tc.name == "runtime")
	h.saveJSON(prefix+"-alignment.json", alignment)
	result := map[string]any{"status": "PASS", "executable_sha256": digest(exe), "alignments_checked": len(alignment)}
	if mode == "dwarf" {
		debug := readJSON(filepath.Join(app, "native/bao-debug.json"))
		check(debug["stripped"] == true, "Linux C++ debug information not stripped")
		result["debug"] = debug
	}
	return result
}

// Exercise the shared C ABI with integer/FP register exhaustion, mixed/narrow
// stack slots and pointers in addition to the C++ lifecycle exports.
func (h *harness) cppLinuxScalars(arch, compiler, compilerFlags, archiveTool string, container func(bool, ...string) []string) {
	flags := strings.Replace(compilerFlags, "-std=c++20", "-std=gnu11 -x c", 1)
	h.run("cpp-scalars-compile.log", h.root, nil, container(false, "set -eu\n"+compiler+" "+flags+" -c /testdata/bindings_integration.c -o /work/scalars.o\n"+archiveTool+" rcs /work/scalars.a /work/scalars.o")...)
	app := filepath.Join(h.dst, "scalar-consumer")
	require(os.Mkdir(app, 0755))
	command := "/work/bao-linux build -target " + h.target + " -sysroot " + cppLinuxSysroot(arch) + " -bindings dwarf -o /work/scalar-consumer/native"
	for _, symbol := range scalarBindingSymbols {
		command += " -symbol " + symbol
	}
	h.run("cpp-scalars-producer.log", h.root, nil, container(false, command+" /work/scalars.a")...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-bindings-check\ngo 1.26.0\n"), 0644))
	copyFile(filepath.Join(h.root, "testdata/bindings_consumer.go.tmpl"), filepath.Join(app, "main.go"))
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": arch})
	exe := filepath.Join(h.dst, "scalar-executable")
	h.run("cpp-scalars-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out := string(h.run("cpp-scalars-run-"+procs+".log", h.root, nil, h.cppLinuxExec(arch, "scalar-executable", procs, nil)...))
		check(strings.Contains(out, "PASS: typed scalars"), "Linux scalar ABI validation failed: %s", out)
	}
	h.results["scalar_abi"] = map[string]any{"status": "PASS", "source_language": "C", "binding": "DWARF-inferred typed assembly; no purego module", "checks": "integer/FP spills, mixed and narrow arguments, uint32, pointer result, TLS, scheduler progress", "executable_sha256": digest(exe)}
}
