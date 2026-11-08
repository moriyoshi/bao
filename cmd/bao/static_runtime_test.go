package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ordinary COFF leaf code calling one undefined C ABI function through REL32.
// The translator's normal import catalog supplies the shared runtime mapping.
func staticRuntimeImportCOFF(symbol string) []byte {
	const reloc, symtab, strtab = 66, 76, 112
	data := make([]byte, strtab+4+len(symbol)+1)
	binary.LittleEndian.PutUint16(data, 0x8664)
	binary.LittleEndian.PutUint16(data[2:], 1)
	binary.LittleEndian.PutUint32(data[8:], symtab)
	binary.LittleEndian.PutUint32(data[12:], 2)
	copy(data[20:], ".text")
	binary.LittleEndian.PutUint32(data[36:], 6)
	binary.LittleEndian.PutUint32(data[40:], 60)
	binary.LittleEndian.PutUint32(data[44:], reloc)
	binary.LittleEndian.PutUint16(data[52:], 1)
	binary.LittleEndian.PutUint32(data[56:], 0x60500020)
	copy(data[60:], []byte{0xe8, 0, 0, 0, 0, 0xc3})
	binary.LittleEndian.PutUint32(data[reloc:], 1)
	binary.LittleEndian.PutUint32(data[reloc+4:], 1)
	binary.LittleEndian.PutUint16(data[reloc+8:], 4)
	copy(data[symtab:], "answer")
	binary.LittleEndian.PutUint16(data[symtab+12:], 1)
	binary.LittleEndian.PutUint16(data[symtab+14:], 0x20)
	data[symtab+16] = 2
	binary.LittleEndian.PutUint32(data[symtab+18+4:], 4)
	binary.LittleEndian.PutUint16(data[symtab+18+14:], 0x20)
	data[symtab+18+16] = 2
	binary.LittleEndian.PutUint32(data[strtab:], uint32(len(data)-strtab))
	copy(data[strtab+4:], symbol)
	return data
}

func TestRequireStaticRuntimeRejectsFallbackAndRollsBack(t *testing.T) {
	for _, row := range []struct{ symbol, library string }{{"__cxa_throw", "libstdc++-6.dll"}, {"_Unwind_Resume", "libgcc_s_seh-1.dll"}} {
		t.Run(row.symbol, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.obj")
			original := staticRuntimeImportCOFF(row.symbol)
			if err := os.WriteFile(input, original, 0644); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr strings.Builder
			ordinary := filepath.Join(dir, "ordinary")
			if err := run([]string{"build", "-target", "windows/amd64", "-symbol", "answer", "-o", ordinary, input}, &stdout, &stderr); err != nil {
				t.Fatalf("ordinary shared-runtime baseline failed: %v", err)
			}
			if err := verifyStaticRuntimeImports(ordinary); err == nil || !strings.Contains(err.Error(), row.library) {
				t.Fatalf("baseline did not expose expected dependency %s: %v", row.library, err)
			}
			output := filepath.Join(dir, "strict")
			err := run([]string{"build", "-require-static-runtime", "-target", "windows/amd64", "-symbol", "answer", "-o", output, input}, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), "static language runtime required") || !strings.Contains(err.Error(), row.library) {
				t.Fatalf("strict runtime fallback accepted or wrong failure: %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("rejected static build published output")
			}
			leftovers, err := filepath.Glob(filepath.Join(dir, ".bao-build-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("rejected static build retained private staging: %v %v", leftovers, err)
			}
			current, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(current, original) {
				t.Fatal("runtime rejection changed original native input")
			}
		})
	}
}

func TestStaticRuntimeChecksImplicitGoImportsWithoutManifestEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bao-manifest.json"), []byte(`{"imports":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "symbols_linux_arm64.go")
	if err := os.WriteFile(path, []byte("package native\n//go:cgo_import_dynamic _ _ \"libgcc_s.so.1\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyStaticRuntimeImports(dir); err == nil || !strings.Contains(err.Error(), "libgcc_s.so.1") {
		t.Fatalf("implicit unwind registration escaped static-runtime contract: %v", err)
	}
	if err := os.WriteFile(path, []byte("package native\n//go:cgo_import_dynamic libc_abort abort \"libc.so.6\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyStaticRuntimeImports(dir); err != nil {
		t.Fatalf("OS library rejected by language-runtime contract: %v", err)
	}
}

func TestRequireStaticRuntimeRecordsSuccessfulContract(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.obj")
	if err := os.WriteFile(input, staticLeafCOFF("answer"), 0644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "strict")
	var stdout, stderr strings.Builder
	if err := run([]string{"build", "-require-static-runtime", "-target", "windows/amd64", "-symbol", "answer", "-o", output, input}, &stdout, &stderr); err != nil {
		t.Fatalf("runtime-free strict build failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(output, "bao-build.json"))
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Required bool `json:"require_static_runtime"`
	}
	if err := json.Unmarshal(data, &provenance); err != nil || !provenance.Required {
		t.Fatalf("successful contract missing from provenance: %s %v", data, err)
	}
}

func TestRequireStaticRuntimeIncludesDynamicallyLoadedData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bao-manifest.json")
	for _, row := range []struct {
		dll    string
		reject bool
	}{{"libstdc++-6.dll", true}, {"kernel32.dll", false}} {
		b, err := json.Marshal(map[string]any{"imports": []any{}, "data_imports": []any{map[string]string{"DLL": row.dll}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0644); err != nil {
			t.Fatal(err)
		}
		err = verifyStaticRuntimeImports(dir)
		if (err != nil) != row.reject {
			t.Fatalf("data-only %s import: %v", row.dll, err)
		}
	}
}
