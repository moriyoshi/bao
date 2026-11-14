package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigSymbolEdits(t *testing.T) {
	body := `{"schema":1,"wrap":["pthread_create","recv"],"redefine_symbols":["a=b"],"redefine_symbol_files":["renames.txt"],
	"prefix_symbols":{"vendor/z.a":"z_","/abs/a.a":"a_"}}`
	_, fs, _, err := configFlags(t, "build", body, "-target", "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string) string { return fs.Lookup(name).Value.String() }
	if value("wrap") != "pthread_create,recv" || value("redefine-sym") != "a=b" {
		t.Fatalf("wrap=%q redefine-sym=%q", value("wrap"), value("redefine-sym"))
	}
	// Paths are relative to the config file; prefixes are sorted by path.
	files, prefixes := value("redefine-syms"), strings.Split(value("prefix-symbols"), ",")
	if filepath.Base(files) != "renames.txt" || !filepath.IsAbs(files) {
		t.Fatalf("redefine-syms=%q", files)
	}
	if len(prefixes) != 2 || prefixes[0] != "/abs/a.a=a_" || !filepath.IsAbs(prefixes[1]) || !strings.HasSuffix(prefixes[1], filepath.Join("vendor", "z.a")+"=z_") {
		t.Fatalf("prefix-symbols=%q", prefixes)
	}
	_, fs, _, err = configFlags(t, "build", body, "-target", "linux/arm64", "-wrap", "send")
	if err != nil || fs.Lookup("wrap").Value.String() != "send" {
		t.Fatalf("command line did not replace wrap: %v", err)
	}
}

func TestSymbolEditFlags(t *testing.T) {
	dir := t.TempDir()
	renames := filepath.Join(dir, "renames.txt")
	if err := os.WriteFile(renames, []byte("# glue\nrecv pythago_recv\nsend pythago_send\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := symbolEditFlags{redefineFiles: symbolFlags{renames}, redefine: symbolFlags{"poll=pythago_poll"}, wrap: symbolFlags{"connect"}}
	e, err := f.edits()
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Rename) != 3 || e.Rename["recv"] != "pythago_recv" || e.Rename["poll"] != "pythago_poll" || len(e.Wrap) != 1 {
		t.Fatalf("%+v", e)
	}
	for _, bad := range []symbolEditFlags{
		{redefine: symbolFlags{"poll"}},
		{redefine: symbolFlags{"=x"}},
		{redefine: symbolFlags{"recv=other"}, redefineFiles: symbolFlags{renames}},
		{redefine: symbolFlags{"connect=x"}, wrap: symbolFlags{"connect"}},
	} {
		if _, err := bad.edits(); err == nil || exitCode(err) != 2 {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestPrefixSymbolsMustNameAComponent(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a.a"), filepath.Join(dir, "b.a"), filepath.Join(dir, "other.a")}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("!<arch>\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	components := []editComponent{{paths[0], []byte("!<arch>\n")}, {paths[1], []byte("!<arch>\n")}}
	for _, tc := range []struct {
		prefixes []string
		want     string
	}{
		{[]string{paths[2] + "=x_"}, "names neither"},
		{[]string{paths[0] + "=x_", paths[0] + "=y_"}, "both x_ and y_"},
		{[]string{paths[0]}, "expected PATH=PREFIX"},
		{[]string{paths[0] + "="}, "expected PATH=PREFIX"},
	} {
		f := symbolEditFlags{prefixes: tc.prefixes}
		if _, err := f.applyBuild(components, os.Stderr); err == nil || !strings.Contains(err.Error(), tc.want) || exitCode(err) != 2 {
			t.Errorf("%q: %v", tc.prefixes, err)
		}
	}
	// The same file named through another path is the same component.
	f := symbolEditFlags{prefixes: symbolFlags{filepath.Join(dir, ".", "a.a") + "=x_", paths[1] + "=x_"}}
	record, err := f.applyBuild(components, os.Stderr)
	if err != nil || len(record.Prefixes) != 2 {
		t.Fatalf("%+v %v", record, err)
	}
}

func TestSymbolEditUsage(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "leaf.obj")
	if err := os.WriteFile(input, staticLeafCOFF("answer"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	err := run([]string{"build", "-target", "windows/amd64", "-wrap", "answer", "-o", filepath.Join(dir, "out"), input}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "only Linux ELF") || exitCode(err) != 2 {
		t.Fatalf("build: %v", err)
	}
	if err := run([]string{"objcopy", "-wrap", "answer", input}, &stdout, &stderr); err == nil || exitCode(err) != 2 {
		t.Fatalf("objcopy without output: %v", err)
	}
	if err := run([]string{"objcopy", "-wrap", "answer", input, filepath.Join(dir, "x.obj")}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "not an ELF object") {
		t.Fatalf("objcopy of COFF: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "x.obj")); err == nil {
		t.Fatal("objcopy wrote an output after failing")
	}
}
