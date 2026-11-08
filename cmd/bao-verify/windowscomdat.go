package main

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"strings"
)

func (h *harness) windowsCOMDAT(arch, cxxRuntime string) {
	objects := []string{}
	duplicates := map[string]int{}
	for _, source := range []string{"comdat_a.cpp", "comdat_b.cpp"} {
		obj := filepath.Join(h.dst, source+".obj")
		args := h.windowsCompile(h.windowsCXX, filepath.Join(h.root, "examples/windows_runtime", source), obj, arch, true)
		if h.windowsDriver == "msvc" || h.windowsDriver == "clang-cl" {
			clean := []string{args[0], "/MD"}
			for _, a := range args[1:] {
				if a != "/Zl" {
					clean = append(clean, a)
				}
			}
			args = clean
		}
		h.run("windows-"+source+"-compile.log", h.root, nil, args...)
		f, err := pe.NewFile(bytes.NewReader(read(obj)))
		require(err)
		for _, s := range f.Symbols {
			if s.StorageClass == 2 && s.SectionNumber > 0 && f.Sections[s.SectionNumber-1].Characteristics&pe.IMAGE_SCN_LNK_COMDAT != 0 {
				duplicates[s.Name]++
			}
		}
		require(f.Close())
		objects = append(objects, obj)
	}
	count := 0
	for _, n := range duplicates {
		if n > 1 {
			count++
		}
	}
	check(count >= 4, "C++ compiler emitted only %d duplicate COMDAT symbols", count)
	archive := filepath.Join(h.dst, "comdat.a")
	h.run("windows-comdat-archive.log", h.root, nil, append([]string{h.windowsAR, "rcS", archive}, objects...)...)
	hash := digest(archive)
	app := filepath.Join(h.dst, "comdat")
	require(os.Mkdir(app, 0755))
	args := []string{h.bao, "build", "-target", h.target, "-windows-cxx-runtime", cxxRuntime, "-bindings", filepath.Join(h.root, "examples/windows_runtime/comdat-signatures.json"), "-o", filepath.Join(app, "native")}
	for _, s := range []string{"a", "b", "check", "state"} {
		args = append(args, "-symbol", "bao_windows_comdat_"+s)
	}
	args = h.staticWindowsBuildArgs(args)
	h.run("windows-comdat-producer.log", h.root, nil, append(args, archive)...)
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte("module bao-windows-comdat\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(windowsCOMDATConsumer), 0644))
	cross := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": arch})
	exe := filepath.Join(h.dst, "comdat.exe")
	h.run("windows-comdat-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	checkWindowsFunctionTable(exe, arch)
	for _, procs := range []string{"1", "4"} {
		out := h.run("windows-comdat-run-"+procs+".log", h.root, map[string]string{"GOMAXPROCS": procs}, h.windowsExecute(exe)...)
		check(strings.Contains(string(out), "PASS: Windows COMDAT"), "Windows COMDAT execution failed")
	}
	negative := filepath.Join(h.dst, "comdat-negative-unwind")
	copyTree(app, negative)
	disableWindowsUnwind(negative, arch)
	negativeExe := filepath.Join(h.dst, "comdat-negative-unwind.exe")
	h.run("windows-comdat-negative-unwind-build.log", negative, cross, h.goTool, "build", "-o", negativeExe, ".")
	out, err := h.command("windows-comdat-negative-unwind-run.log", h.root, nil, h.windowsExecute(negativeExe)...)
	check(err != nil && strings.Contains(string(out), "Windows COMDAT identity/initialization/exception failure") && !strings.Contains(string(out), "PASS:"), "COMDAT unwind negative control failed: %v %s", err, out)
	check(digest(archive) == hash, "COMDAT archive changed")
	h.results["windows_comdat"] = map[string]any{"archive_sha256": hash, "duplicate_symbols": count, "translation_units": 2, "features": []string{"inline functions", "template instantiations", "vtables", "static initialization and finalization", "TLS identity", "throw/catch and RAII", "unwind lookup"}, "negative_controls": []string{"native unwind metadata"}}
}

const windowsCOMDATConsumer = `package main
import (
 "fmt"
 "runtime"
 native "bao-windows-comdat/native"
)
func main() {
 runtime.LockOSThread()
 if native.Check()!=42 || native.A()!=42 || native.B()!=42 || native.State()!=202 { panic("Windows COMDAT identity/initialization/exception failure") }
 native.TLSFinalizeCurrentThread()
 native.Shutdown()
 native.Shutdown()
 if native.State()!=222 { panic("Windows COMDAT finalization failure") }
 fmt.Println("PASS: Windows COMDAT: shared code, data, TLS, vtables, unwind and finalizers")
}
`
