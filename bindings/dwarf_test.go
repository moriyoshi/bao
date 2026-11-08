package bindings

import (
	"bytes"
	"crypto/sha256"
	"debug/dwarf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInferOptimizedCAndRustCompilerObjects(t *testing.T) {
	for _, format := range []string{"macho", "elf"} {
		t.Run(format, func(t *testing.T) {
			c := fixture(t, "c_"+format+".bin")
			before := bytes.Clone(c)
			symbols := []string{"infer_mix", "infer_pointer", "infer_void", "infer_optimized", "infer_inline"}
			got, err := Infer("C object", c, symbols)
			if err != nil {
				t.Fatal(err)
			}
			want := Manifest{Schema: 1, ABI: "c", Functions: []Function{{Name: "InferMix", Symbol: "infer_mix", Params: []string{"int8", "uint16", "int32", "uint64", "float32", "float64"}, Result: "uint64"}, {Name: "InferPointer", Symbol: "infer_pointer", Params: []string{"pointer", "uintptr"}, Result: "uintptr"}, {Name: "InferVoid", Symbol: "infer_void", Params: []string{}, Result: "void"}, {Name: "InferOptimized", Symbol: "infer_optimized", Params: []string{"int32", "float64"}, Result: "int32"}, {Name: "InferInline", Symbol: "infer_inline", Params: []string{"uint64", "uint32"}, Result: "uint64"}}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("C inference:\n%+v\nwant %+v", got, want)
			}
			if !bytes.Equal(c, before) {
				t.Fatal("inference mutated the original compiler object")
			}
			rust := fixture(t, "rust_"+format+".bin")
			rs := []string{"infer_rust_mix", "infer_rust_void", "infer_rust_usize", "infer_rust_ref", "infer_rust_optimized"}
			got, err = Infer("Rust object", rust, rs)
			if err != nil {
				t.Fatal(err)
			}
			want = Manifest{Schema: 1, ABI: "c", Functions: []Function{{Name: "InferRustMix", Symbol: rs[0], Params: []string{"uint64", "float64", "pointer", "int8"}, Result: "float64"}, {Name: "InferRustVoid", Symbol: rs[1], Params: []string{}, Result: "void"}, {Name: "InferRustUsize", Symbol: rs[2], Params: []string{"uintptr"}, Result: "uintptr"}, {Name: "InferRustRef", Symbol: rs[3], Params: []string{"pointer"}, Result: "uint64"}, {Name: "InferRustOptimized", Symbol: rs[4], Params: []string{"int16", "float32"}, Result: "int16"}}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Rust inference:\n%+v\nwant %+v", got, want)
			}
			cpp := fixture(t, "cpp_"+format+".bin")
			got, err = Infer("C++ specification/reference", cpp, []string{"_ZN7fixture4Spec6methodEi", "infer_spec", "infer_reference"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Functions[0].Result != "int32" || !reflect.DeepEqual(got.Functions[2].Params, []string{"pointer"}) {
				t.Fatal("specification or C++ reference normalization failed", got)
			}
		})
	}
}

func ordinaryArchive(parts ...[]byte) []byte {
	b := []byte("!<arch>\n")
	for i, p := range parts {
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", fmt.Sprintf("object%d.o/", i), 0, 0, 0, 0644, len(p))
		b = append(b, header...)
		b = append(b, p...)
		if len(p)%2 != 0 {
			b = append(b, '\n')
		}
	}
	return b
}

func TestInferOrdinaryArchivesAndAmbiguity(t *testing.T) {
	for _, format := range []string{"macho", "elf"} {
		c, rust := fixture(t, "c_"+format+".bin"), fixture(t, "rust_"+format+".bin")
		input := ordinaryArchive(c, rust)
		m, err := Infer("library.a", input, []string{"infer_rust_ref", "infer_mix"})
		if err != nil {
			t.Fatal(err)
		}
		if m.Functions[0].Symbol != "infer_rust_ref" || m.Functions[1].Symbol != "infer_mix" {
			t.Fatal("requested export order changed")
		}
		if _, err := Infer("duplicate.a", ordinaryArchive(c, c), []string{"infer_mix"}); err == nil || !strings.Contains(err.Error(), "multiple archive members") {
			t.Fatal("duplicate definitions not rejected", err)
		}
	}
}

func TestInferRejectsUnsupportedOrMissingSignatures(t *testing.T) {
	for _, format := range []string{"macho", "elf"} {
		for _, row := range []struct{ file, symbol, reason string }{{"c_", "infer_variadic", "variadic"}, {"c_", "infer_callback", "callback"}, {"c_", "infer_aggregate", "aggregate"}, {"c_", "infer_bool", "unsupported base"}, {"rust_", "infer_rust_callback", "callback"}, {"rust_", "infer_rust_aggregate", "aggregate"}} {
			t.Run(format+"/"+row.symbol, func(t *testing.T) {
				_, err := Infer("fixture", fixture(t, row.file+format+".bin"), []string{row.symbol})
				if err == nil || !strings.Contains(err.Error(), row.reason) {
					t.Fatalf("unsupported signature accepted or wrong diagnostic: %v", err)
				}
			})
		}
	}
	if _, err := Infer("stripped", fixture(t, "c_no_debug_elf.bin"), []string{"infer_mix"}); err == nil || !strings.Contains(err.Error(), "no source-level DWARF") {
		t.Fatal("unwind-only object guessed a signature", err)
	}
	if _, err := Infer("alternate convention", fixture(t, "cc_macho.bin"), []string{"infer_foreign_cc"}); err == nil || !strings.Contains(err.Error(), "calling convention") {
		t.Fatal("foreign calling convention accepted", err)
	}
	if _, err := Infer("C", fixture(t, "c_macho.bin"), nil); err == nil {
		t.Fatal("inference without explicit C ABI exports accepted")
	}
	if _, err := Infer("C", fixture(t, "c_macho.bin"), []string{"not_an_export"}); err == nil {
		t.Fatal("nonexistent export accepted")
	}
}

func node(off dwarf.Offset, tag dwarf.Tag, fields ...dwarf.Field) *dwarfNode {
	return &dwarfNode{entry: dwarf.Entry{Offset: off, Tag: tag, Field: fields}, unit: &dwarfUnit{types: 1}}
}
func field(attr dwarf.Attr, value any) dwarf.Field { return dwarf.Field{Attr: attr, Val: value} }

func TestOptimizedOmittedParameterInheritanceAndConflicts(t *testing.T) {
	integer := node(1, dwarf.TagBaseType, field(dwarf.AttrName, "int"), field(dwarf.AttrByteSize, int64(4)), field(dwarf.AttrEncoding, int64(5)))
	param := node(2, dwarf.TagFormalParameter, field(dwarf.AttrType, dwarf.Offset(1)))
	declaration := node(3, dwarf.TagSubprogram, field(dwarf.AttrName, "exported"), field(dwarf.AttrType, dwarf.Offset(1)))
	declaration.children = []*dwarfNode{param}
	definition := node(4, dwarf.TagSubprogram, field(dwarf.AttrAbstractOrigin, dwarf.Offset(3)))
	tree := &dwarfTree{nodes: map[dwarf.Offset]*dwarfNode{1: integer, 2: param, 3: declaration, 4: definition}, functions: []*dwarfNode{definition}}
	f, err := tree.function("exported")
	if err != nil || !reflect.DeepEqual(f.Params, []string{"int32"}) {
		t.Fatal("optimized omitted formal parameter not recovered", f, err)
	}
	definition.entry.Field = append(definition.entry.Field, field(dwarf.AttrCalling, int64(2)))
	if _, err := tree.function("exported"); err == nil {
		t.Fatal("program calling convention accepted")
	}
	definition.entry.Field = definition.entry.Field[:1]
	other := node(5, dwarf.TagSubprogram, field(dwarf.AttrName, "exported"), field(dwarf.AttrType, dwarf.Offset(1)))
	tree.nodes[5] = other
	tree.functions = append(tree.functions, other)
	if _, err := tree.function("exported"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatal("independent conflicting origin not rejected", err)
	}
	tree.functions = tree.functions[:1]
	declaration.entry.Field = append(declaration.entry.Field, field(dwarf.AttrSpecification, dwarf.Offset(4)))
	if _, err := tree.function("exported"); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatal("cyclic origin/specification accepted", err)
	}
}

func TestCompilerFixturesContainFullOptimizedDebugEvidence(t *testing.T) {
	for _, row := range []struct {
		file, symbol string
		origin, spec bool
	}{{"c_macho.bin", "infer_inline", true, false}, {"cpp_macho.bin", "_ZN7fixture4Spec6methodEi", true, true}, {"c_elf.bin", "infer_inline", true, false}, {"rust_macho.bin", "infer_rust_mix", false, false}, {"rust_elf.bin", "infer_rust_mix", false, false}} {
		data, _, err := objectDWARF(fixture(t, row.file), map[string]bool{row.symbol: true})
		if err != nil || data == nil {
			t.Fatal("missing real compiler DWARF", row.file, err)
		}
		r := data.Reader()
		types, origins, specs := 0, 0, 0
		for {
			e, err := r.Next()
			if err != nil {
				t.Fatal(err)
			}
			if e == nil {
				break
			}
			if isTypeTag(e.Tag) {
				types++
			}
			if e.Val(dwarf.AttrAbstractOrigin) != nil {
				origins++
			}
			if e.Val(dwarf.AttrSpecification) != nil {
				specs++
			}
		}
		if types < 3 || row.origin && origins == 0 || row.spec && specs == 0 {
			t.Fatalf("%s lost optimized type/origin evidence: types%d origins%d specs%d", row.file, types, origins, specs)
		}
	}
}

func TestCompilerFixtureProvenance(t *testing.T) {
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(fixture(t, "provenance.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for name, want := range manifest.Files {
		got := fmt.Sprintf("%x", sha256.Sum256(fixture(t, name)))
		if got != want {
			t.Fatalf("%s changed without updating compiler provenance", name)
		}
	}
}

func TestSameOriginConflictingSignaturesAndPartialDebugRejected(t *testing.T) {
	integer := node(1, dwarf.TagBaseType, field(dwarf.AttrName, "int"), field(dwarf.AttrByteSize, int64(4)), field(dwarf.AttrEncoding, int64(5)))
	float := node(2, dwarf.TagBaseType, field(dwarf.AttrName, "double"), field(dwarf.AttrByteSize, int64(8)), field(dwarf.AttrEncoding, int64(4)))
	base := node(3, dwarf.TagSubprogram, field(dwarf.AttrName, "exported"), field(dwarf.AttrType, dwarf.Offset(1)))
	a := node(4, dwarf.TagSubprogram, field(dwarf.AttrAbstractOrigin, dwarf.Offset(3)), field(dwarf.AttrType, dwarf.Offset(2)))
	b := node(5, dwarf.TagSubprogram, field(dwarf.AttrAbstractOrigin, dwarf.Offset(3)))
	tree := &dwarfTree{nodes: map[dwarf.Offset]*dwarfNode{1: integer, 2: float, 3: base, 4: a, 5: b}, functions: []*dwarfNode{a, b}}
	if _, err := tree.function("exported"); err == nil {
		t.Fatal("a conflicting optimized signature was hidden by a later matching origin")
	}
	partial := node(6, dwarf.TagSubprogram, field(dwarf.AttrName, "partial"))
	partial.unit.types = 0
	tree.nodes[6] = partial
	tree.functions = []*dwarfNode{partial}
	if _, err := tree.function("partial"); err == nil {
		t.Fatal("line-table-only information guessed zero parameters and void result")
	}
}
