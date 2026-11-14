package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/bindings"
	"github.com/moriyoshi/bao/linuxelf"
	"github.com/moriyoshi/bao/pecoff"
	"github.com/moriyoshi/bao/translate"
)

// largeTableEntries is the per-kind entry count for the large-library checks.
// The gpui-go aarch64-pc-windows-gnullvm library has 180,745 COFF sections and
// 33,203 .pdata sections; unrolled init code ran the compiler out of memory.
const largeTableEntries = 40000

func syntheticWindowsPlan(arch string, n int) *pecoff.Plan {
	p := &pecoff.Plan{Arch: arch, Namespace: "bao_test_", Exports: []string{"answer"}, Runtime: true, TLS: pecoff.TLSPlan{Symbol: "bao_test_tls", Size: 16, Alignment: 8}}
	tables := func(kind string, n int, order string) []pecoff.Table {
		ts := make([]pecoff.Table, n)
		for i := range ts {
			ts[i] = pecoff.Table{Symbol: fmt.Sprintf("bao_test_%s%d", kind, i), Count: i%7 + 1, Order: order}
			if order == ".ctors" && i%2 == 0 {
				ts[i].Order = ".init_array"
			}
		}
		return ts
	}
	for i := 0; i < n; i++ {
		p.Imports = append(p.Imports, pecoff.Import{Local: fmt.Sprintf("bao_test_imp_f%d", i), Name: fmt.Sprintf("F%d", i), DLL: fmt.Sprintf("d%d.dll", i%5)})
		p.DataImports = append(p.DataImports, pecoff.DataImport{Symbol: fmt.Sprintf("bao_test_data%d", i), Name: fmt.Sprintf("D%d", i), DLL: "kernel32.dll", Offset: uint32(i % 3 * 8), Addend: uint64(i % 2)})
		p.Alignments = append(p.Alignments, pecoff.Alignment{Symbol: fmt.Sprintf("bao_test_section%d", i), Bytes: 1 << (i % 6)})
	}
	p.Unwind = tables("pdata", n, "")
	p.UnwindRoots = tables("root", n, "")
	p.Constructors = tables("ctor", n, ".ctors")
	p.CInitializers = tables("xi", n, "")
	p.PreTerminators = tables("xp", n, "")
	p.Terminators = tables("xt", n, "")
	p.TLSCallbacks = tables("xl", n, "")
	p.TLSInitializers = tables("xd", n, "")
	return p
}

func syntheticLinuxPlan(n int) *linuxelf.Plan {
	p := &linuxelf.Plan{Arch: "amd64", Namespace: "bao_test_", TLSTemplateSymbol: "bao_test_tls", TLSTemplateSize: 16, TLSTemplateAlignment: 8,
		Imports: []linuxelf.Import{{Local: "bao_test_imp_a", Remote: "a", Library: "liba.so.1"}, {Local: "bao_test_imp_b", Remote: "b", Library: "libb.so.1"}}}
	for i := 0; i < n; i++ {
		p.Fixups = append(p.Fixups, linuxelf.Fixup{Location: fmt.Sprintf("bao_test_fixup%d", i), Import: p.Imports[i%2].Local, Addend: int64(i%3 - 1)})
		p.LocalFixups = append(p.LocalFixups, linuxelf.LocalFixup{Location: fmt.Sprintf("bao_test_place%d", i), Target: fmt.Sprintf("bao_test_target%d", i), Subtract: fmt.Sprintf("bao_test_sub%d", i), Addend: int64(i % 5), Width: 4 << (i % 2)})
		p.Unwind = append(p.Unwind, fmt.Sprintf("bao_test_eh%d", i))
		p.Constructors = append(p.Constructors, linuxelf.Table{Symbol: fmt.Sprintf("bao_test_init%d", i), Count: i%7 + 1})
		p.Finalizers = append(p.Finalizers, linuxelf.Table{Symbol: fmt.Sprintf("bao_test_fini%d", i), Count: i%7 + 1})
	}
	return p
}

// syntheticSharedObjectPlan adds a shared-object image whose import fixups
// are image offsets, some of them versioned, and an export table.
func syntheticSharedObjectPlan(n int) *linuxelf.Plan {
	p := syntheticLinuxPlan(n)
	p.Arch = "arm64"
	p.Imports[1].Version = "GLIBC_2.17"
	so := &linuxelf.SharedObject{BaseSymbol: "bao_test_so_base", MaxPageSize: 65536, Writable: []linuxelf.Range{{Start: 0x20000, End: 0x30000}}, RELRO: []linuxelf.Range{{Start: 0x20000, End: 0x24000}}}
	for i := 0; i < n; i++ {
		p.Fixups[i].Location, p.Fixups[i].Offset = so.BaseSymbol, uint64(0x20000+8*i)
		so.Exports = append(so.Exports, linuxelf.Export{Name: fmt.Sprintf("Export%06d", i), Kind: "func", Offset: uint64(16 * i)})
	}
	p.SharedObject = so
	return p
}

func syntheticDarwinPlan(n int) *translate.TLSProbe {
	p := &translate.TLSProbe{Arch: "arm64", Namespace: "bao_test_", TemplateSymbol: "bao_test_tls", TemplateSize: 16, TemplateAlignment: 8,
		Imports: []translate.ImportBinding{{Local: "bao_test_imp_a", Remote: "_a", Library: "/usr/lib/libSystem.B.dylib"}, {Local: "bao_test_imp_b", Remote: "_b", Library: "/usr/lib/libSystem.B.dylib"}}}
	for i := 0; i < n; i++ {
		p.Fixups = append(p.Fixups, translate.PointerFixup{Symbol: fmt.Sprintf("bao_test_fixup%d", i), ImportLocal: p.Imports[i%2].Local, Addend: uint64(i % 3)})
		p.Unwind = append(p.Unwind, translate.UnwindSection{Symbol: fmt.Sprintf("bao_test_eh%d", i), FDEOffsets: []uint32{0, uint32(i%5*16 + 16)}})
		p.Constructors = append(p.Constructors, translate.ConstructorTable{Symbol: fmt.Sprintf("bao_test_init%d", i), Count: uint64(i%7 + 1)})
	}
	return p
}

type generatedPackage struct {
	name, goos, goarch, file string
	source                   func(n int) ([]byte, []byte, error)
}

func generatedPackages() []generatedPackage {
	var packages []generatedPackage
	for _, arch := range []string{"amd64", "arm64"} {
		packages = append(packages, generatedPackage{"windows" + arch, "windows", arch, "symbols_windows_" + arch, func(n int) ([]byte, []byte, error) {
			return windowsSource(syntheticWindowsPlan(arch, n), "windows"+arch)
		}})
	}
	packages = append(packages, generatedPackage{"linux", "linux", "amd64", "symbols_linux_amd64", func(n int) ([]byte, []byte, error) {
		return linuxSource(syntheticLinuxPlan(n), "linux", []string{"answer"})
	}})
	packages = append(packages, generatedPackage{"linuxso", "linux", "arm64", "symbols_linux_arm64", func(n int) ([]byte, []byte, error) {
		return linuxSource(syntheticSharedObjectPlan(n), "linuxso", []string{"answer"})
	}})
	packages = append(packages, generatedPackage{"darwin", "darwin", "arm64", "symbols_darwin_arm64", func(n int) ([]byte, []byte, error) {
		return darwinSource(syntheticDarwinPlan(n), "darwin", []string{"answer"}, nil, true)
	}})
	return packages
}

// codeShape counts declarations and statements inside function bodies.
// Table contents are package-level composite literals and are not counted.
func codeShape(t *testing.T, source []byte) map[string]int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	shape := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		shape["func"]++
		if fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n.(type) {
			case ast.Stmt, *ast.CallExpr:
				shape[fmt.Sprintf("%T", n)]++
			}
			return true
		})
	}
	return shape
}

func TestGeneratedCodeDoesNotGrowWithTables(t *testing.T) {
	for _, pkg := range generatedPackages() {
		t.Run(pkg.name, func(t *testing.T) {
			small, smallAsm, err := pkg.source(3)
			if err != nil {
				t.Fatal(err)
			}
			large, asm, err := pkg.source(1000)
			if err != nil {
				t.Fatal(err)
			}
			want, got := codeShape(t, small), codeShape(t, large)
			if fmt.Sprint(want) != fmt.Sprint(got) {
				t.Fatalf("function code grows with table entries:\n3 entries:    %v\n1000 entries: %v", want, got)
			}
			// Table entries are assembler data, not one accessor each. Only a
			// Windows function import has its own call stub.
			growth := strings.Count(string(asm), "TEXT ") - strings.Count(string(smallAsm), "TEXT ")
			if pkg.goos == "windows" {
				growth -= 1000 - 3
			}
			if growth != 0 {
				t.Fatalf("assembler functions grow by %d with table entries", growth)
			}
			again, againAsm, err := pkg.source(1000)
			if err != nil || string(again) != string(large) || string(againAsm) != string(asm) {
				t.Fatalf("generated sources are not deterministic: %v", err)
			}
		})
	}
}

// fakePurego stands in for github.com/ebitengine/purego so generated Linux and
// Darwin packages compile without network access.
const fakePurego = `package purego

const RTLD_DEFAULT = 0

func RegisterFunc(fptr any, cfn uintptr) {}

func Dlsym(handle uintptr, name string) (uintptr, error) { return 0, nil }

func SyscallN(fn uintptr, args ...uintptr) (r1, r2, err uintptr) { return }
`

// TestLargeGeneratedPackagesCompile compiles generated packages with tens of
// thousands of table entries and bounds the peak memory of the build. The
// unrolled generator needed about 30 GB for 20,000 Windows ARM64 alignment
// checks and exhausted memory on the gpui-go windows-11-arm runner.
func TestLargeGeneratedPackagesCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles large generated packages")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command unavailable")
	}
	dir := t.TempDir()
	write := func(path, data string) {
		t.Helper()
		path = filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.org/large\n\ngo 1.26\n\nrequire github.com/ebitengine/purego v0.0.0\n\nreplace github.com/ebitengine/purego => ./purego\n")
	write("purego/go.mod", "module github.com/ebitengine/purego\n\ngo 1.26\n")
	write("purego/purego.go", fakePurego)
	// Bazel test actions have no HOME, so the go command has no default cache.
	base := append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local")
	if os.Getenv("GOCACHE") == "" && os.Getenv("HOME") == "" {
		base = append(base, "GOCACHE="+filepath.Join(dir, "gocache"), "GOPATH="+filepath.Join(dir, "gopath"))
	}
	for _, pkg := range generatedPackages() {
		t.Run(pkg.name, func(t *testing.T) {
			source, asm, err := pkg.source(largeTableEntries)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(pkg.name, pkg.file+".go"), string(source))
			write(filepath.Join(pkg.name, pkg.file+".s"), string(asm))
			env := append(base[:len(base):len(base)], "GOOS="+pkg.goos, "GOARCH="+pkg.goarch)
			build := func(args ...string) *os.ProcessState {
				t.Helper()
				cmd := exec.Command(goTool, append([]string{"build"}, args...)...)
				cmd.Dir, cmd.Env = dir, env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("go build %v: %v\n%s", args, err, out)
				}
				return cmd.ProcessState
			}
			// Standard library packages may not be cached for this target yet.
			build("os", "sort", "sync", "syscall", "unsafe", "runtime")
			state := build("./" + pkg.name)
			peak, ok := peakRSS(state)
			if !ok {
				t.Logf("peak memory not measured on %s", runtime.GOOS)
				return
			}
			t.Logf("%d entries per table: peak %d MiB", largeTableEntries, peak>>20)
			if peak > 1536<<20 {
				t.Fatalf("building %d entries per table peaked at %d MiB", largeTableEntries, peak>>20)
			}
		})
	}
}

// Typed bindings replace every PureGo use in a generated Linux package; a
// helper they cannot rewrite fails generation for every Linux consumer.
func TestLinuxSourcesAcceptTypedBindings(t *testing.T) {
	for name, plan := range map[string]*linuxelf.Plan{"archive": syntheticLinuxPlan(3), "shared object": syntheticSharedObjectPlan(3)} {
		t.Run(name, func(t *testing.T) {
			plan.Arch = "arm64"
			source, asm, err := linuxSource(plan, "native", []string{"answer"})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for file, data := range map[string][]byte{"symbols_linux_arm64.go": source, "symbols_linux_arm64.s": asm} {
				if err := os.WriteFile(filepath.Join(dir, file), data, 0644); err != nil {
					t.Fatal(err)
				}
			}
			m := bindings.Manifest{Schema: 1, ABI: "c", Functions: []bindings.Function{{Name: "Answer", Symbol: "answer", Result: "int64"}}}
			if err := bindings.Generate(dir, "native", "linux/arm64", m, []string{"answer"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
