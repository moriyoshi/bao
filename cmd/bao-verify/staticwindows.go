package main

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func (h *harness) staticWindowsBuildArgs(args []string) []string {
	if h.staticWindows && h.staticWindowsCRT != "" {
		args = append(args, "-windows-crt", h.staticWindowsCRT)
	}
	if h.staticWindows {
		args = append(args, "-require-static-runtime")
	}
	for _, p := range h.staticLinkArchives {
		args = append(args, "-link-archive", p)
	}
	for _, p := range h.staticLinkNotices {
		args = append(args, "-link-notice", p)
	}
	return args
}

func (h *harness) windowsStatic() {
	arch := strings.TrimPrefix(h.target, "windows/")
	check(arch == "amd64" || arch == "arm64", "unsupported Windows static target")
	check(h.windowsRunner != "" || runtime.GOOS == "windows" && runtime.GOARCH == arch, "Windows execution requires a matching native host or explicit runner")
	check(h.windowsDriver == "clang" || h.windowsDriver == "mingw", "the static Windows language-runtime suite currently requires GNU Clang or MinGW GCC")
	check(h.staticRuntimeRoot != "", "-static-runtime-root must name the matching MinGW target prefix")
	h.staticWindows = true
	macros := string(h.run("static-crt-macros.log", h.root, nil, h.windowsCXX, "-dM", "-E", "-x", "c++", "-include", "_mingw.h", "-"))
	h.staticWindowsCRT = "msvcrt"
	if strings.Contains(macros, "#define _UCRT ") {
		h.staticWindowsCRT = "ucrt"
	}
	h.env["RUSTUP_TOOLCHAIN"] = "1.99.1"
	h.results["target"] = h.target
	h.results["execution"] = "native Windows " + arch
	if h.windowsRunner != "" {
		h.results["execution"] = "Windows-compatible Wine runner; native Windows not verified"
	}
	h.results["static_cpp_compiler"] = string(h.run("static-cxx-version.log", h.root, nil, h.windowsCXX, "--version"))
	lib := filepath.Join(h.staticRuntimeRoot, "lib")
	if h.windowsDriver == "clang" {
		for _, name := range []string{"libc++.a", "libc++abi.a", "libunwind.a", "libmingwex.a"} {
			h.staticLinkArchives = append(h.staticLinkArchives, filepath.Join(lib, name))
		}
		builtins := strings.TrimSpace(string(h.run("static-builtins-path.log", h.root, nil, h.windowsCC, "--print-libgcc-file-name")))
		h.staticLinkArchives = append(h.staticLinkArchives, builtins)
	} else {
		for _, name := range []string{"libstdc++.a", "libgcc_eh.a", "libgcc.a", "libwinpthread.a", "libmingwex.a"} {
			path := strings.TrimSpace(string(h.run("static-"+name+"-path.log", h.root, nil, h.windowsCXX, "-print-file-name="+name)))
			check(path != name, "compiler cannot locate static archive %s", name)
			h.staticLinkArchives = append(h.staticLinkArchives, path)
		}
	}
	if h.staticWindowsCRT == "ucrt" {
		h.staticLinkArchives = append(h.staticLinkArchives, filepath.Join(lib, "libucrt.a"))
	}
	for _, path := range h.staticLinkArchives {
		check(len(read(path)) > 0, "missing static runtime archive %s", path)
	}
	for _, path := range []string{filepath.Join(h.staticRuntimeRoot, "share/mingw32/COPYING.MinGW-w64-runtime.txt"), filepath.Join(filepath.Dir(h.staticRuntimeRoot), "LICENSE.TXT")} {
		if _, err := os.Stat(path); err == nil {
			h.staticLinkNotices = append(h.staticLinkNotices, path)
		}
	}
	check(len(h.staticLinkNotices) > 0, "matching runtime license notices must be available in the toolchain prefix")
	h.windowsRust(arch)
	h.windowsStd(arch)
	h.windowsLifecycle(arch)
	for _, name := range []string{"lifecycle", "comdat", "primitive-exception"} {
		for i, notice := range h.staticLinkNotices {
			check(digest(notice) == digest(filepath.Join(h.dst, name, "native", fmt.Sprintf("bao-linked-license-%d.txt", i))), "static Windows runtime license was changed or omitted")
		}
	}
	for _, name := range []string{"lifecycle.exe", "comdat.exe", "primitive-exception.exe"} {
		f, err := pe.Open(filepath.Join(h.dst, name))
		require(err)
		libs, err := windowsImportedLibraries(f)
		require(err)
		require(f.Close())
		for _, lib := range libs {
			check(!languageRuntimeLibrary(lib), "static consumer imports language runtime %s", lib)
		}
	}
	manifests := 0
	require(filepath.WalkDir(h.dst, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "bao-manifest.json" {
			return nil
		}
		var m struct {
			Imports     []struct{ DLL string }
			DataImports []struct{ DLL string } `json:"data_imports"`
		}
		require(json.Unmarshal(read(path), &m))
		for _, imp := range append(m.Imports, m.DataImports...) {
			check(!languageRuntimeLibrary(imp.DLL), "static package retains language DLL %s", imp.DLL)
		}
		manifests++
		return nil
	}))
	check(manifests >= 3, "missing static consumer artifact manifests")
	h.results["static_language_runtime"] = map[string]any{"status": "PASS", "archives": h.staticLinkArchives, "license_files_per_cpp_package": len(h.staticLinkNotices), "manifests_audited": manifests, "system_dlls": "remain dynamic", "fully_static": "unsupported by stock Go Windows system API imports"}
	if h.windowsRunner != "" {
		h.results["status"] = "CHECKED_WITH_LIMITATIONS"
	}
}

// debug/pe.ImportedLibraries is an unimplemented stub in the pinned SDK.
// ImportedSymbols reads the actual import directory and includes each DLL.
func windowsImportedLibraries(f *pe.File) ([]string, error) {
	symbols, err := f.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, symbol := range symbols {
		i := strings.LastIndexByte(symbol, ':')
		if i < 0 || i == len(symbol)-1 {
			return nil, fmt.Errorf("invalid PE import %q", symbol)
		}
		seen[strings.ToLower(symbol[i+1:])] = true
	}
	libs := make([]string, 0, len(seen))
	for lib := range seen {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	if len(libs) == 0 {
		return nil, fmt.Errorf("PE consumer has no readable import directory")
	}
	return libs, nil
}

func languageRuntimeLibrary(name string) bool {
	name = strings.ToLower(filepath.Base(name))
	return strings.Contains(name, "libstdc++") || strings.Contains(name, "libgcc_s") || strings.Contains(name, "libc++") || strings.Contains(name, "libunwind") || strings.Contains(name, "winpthread") || strings.HasPrefix(name, "vcruntime") || strings.HasPrefix(name, "msvcp") || strings.HasPrefix(name, "libstd-") || strings.HasPrefix(name, "std-")
}
