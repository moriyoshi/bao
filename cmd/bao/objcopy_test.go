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

func TestConfigSymbolVisibility(t *testing.T) {
	body := `{"schema":1,"wildcard":true,"symbol_visibility":{"libpython.o":{"keep_global_symbols":["Py*"],"keep_global_symbol_files":["api.txt"],
	"localize_hidden":true,"strip_unneeded":true,"weaken_symbols":["w"]}}}`
	_, fs, _, err := configFlags(t, "build", body, "-target", "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string) string { return fs.Lookup(name).Value.String() }
	keep := strings.Split(value("keep-global-symbol"), ",")
	files := value("keep-global-symbols")
	if value("wildcard") != "true" || len(keep) != 1 || !strings.HasSuffix(keep[0], string(filepath.Separator)+"libpython.o=Py*") || !filepath.IsAbs(keep[0]) {
		t.Fatalf("wildcard=%q keep-global-symbol=%q", value("wildcard"), keep)
	}
	component, file, _ := strings.Cut(files, "=")
	if filepath.Base(component) != "libpython.o" || !filepath.IsAbs(file) || filepath.Base(file) != "api.txt" {
		t.Fatalf("keep-global-symbols=%q", files)
	}
	if filepath.Base(value("localize-hidden")) != "libpython.o" || filepath.Base(value("strip-unneeded")) != "libpython.o" || !strings.HasSuffix(value("weaken-symbol"), "libpython.o=w") {
		t.Fatalf("localize-hidden=%q strip-unneeded=%q weaken-symbol=%q", value("localize-hidden"), value("strip-unneeded"), value("weaken-symbol"))
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

func TestScopedFlagsMustNameAComponent(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "a.a"), filepath.Join(dir, "b.a"), filepath.Join(dir, "other.a")}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("!<arch>\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	alias := dir + string(filepath.Separator) + "." + string(filepath.Separator) + "a.a"
	components := []editComponent{{paths[0], []byte("!<arch>\n")}, {paths[1], []byte("!<arch>\n")}}
	for _, tc := range []struct {
		flags symbolEditFlags
		want  string
	}{
		{symbolEditFlags{prefixes: symbolFlags{paths[2] + "=x_"}}, "names neither"},
		{symbolEditFlags{prefixes: symbolFlags{paths[0] + "=x_", paths[0] + "=y_"}}, "both x_ and y_"},
		{symbolEditFlags{prefixes: symbolFlags{paths[0]}}, "expected PATH=PREFIX"},
		{symbolEditFlags{prefixes: symbolFlags{paths[0] + "="}}, "expected PATH=PREFIX"},
		{symbolEditFlags{scoped: true, localize: symbolFlags{paths[2] + "=x"}}, "names neither"},
		{symbolEditFlags{scoped: true, localize: symbolFlags{"x"}}, "expected PATH=VALUE"},
		{symbolEditFlags{scoped: true, stripUnneeded: symbolFlags{paths[0]}, localize: symbolFlags{alias + "=x"}}, "name the same input"},
		{symbolEditFlags{scoped: true, wildcard: true, keepGlobal: symbolFlags{paths[0] + "=[Py"}}, "invalid symbol pattern"},
	} {
		if _, err := tc.flags.resolveBuild(components); err == nil || !strings.Contains(err.Error(), tc.want) || exitCode(err) != 2 {
			t.Errorf("%+v: %v", tc.flags, err)
		}
	}
	// The same file named through another path is the same component, and
	// each component gets only its own binding edits.
	f := symbolEditFlags{scoped: true, prefixes: symbolFlags{alias + "=x_", paths[1] + "=x_"}, localizeHidden: symbolFlags{paths[1]}, keepGlobal: symbolFlags{paths[1] + "=Py_Main"}}
	b, err := f.resolveBuild(components)
	if err != nil || len(b.record.Prefixes) != 2 || b.changesBindings(0) || !b.changesBindings(1) {
		t.Fatalf("%+v %v", b, err)
	}
	if v := b.record.Visibility; len(v) != 1 || v[0].Path != paths[1] || !v[0].LocalizeHidden || len(v[0].KeepGlobal) != 1 {
		t.Fatalf("visibility record %+v", v)
	}
}

func TestVisibilitySpecsReadFiles(t *testing.T) {
	list := filepath.Join(t.TempDir(), "api.txt")
	if err := os.WriteFile(list, []byte("# exported\nPy_Initialize\nPyRun_SimpleString\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := symbolEditFlags{keepGlobalFiles: symbolFlags{list}, keepGlobal: symbolFlags{"pythago_*"}, stripUnneededAll: true, wildcard: true}
	specs, err := f.visibilitySpecs()
	if err != nil || len(specs) != 1 {
		t.Fatalf("%+v %v", specs, err)
	}
	if got := strings.Join(specs[0].KeepGlobal, ","); got != "pythago_*,Py_Initialize,PyRun_SimpleString" || !specs[0].StripUnneeded {
		t.Fatalf("%+v", specs[0])
	}
	v, _ := specs[0].compile(true)
	if !v.KeepGlobal.Match("pythago_thread_start") || v.KeepGlobal.Match("PyList_New") {
		t.Fatal("compiled matcher")
	}
}

func TestSymbolEditUsage(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "leaf.obj")
	if err := os.WriteFile(input, staticLeafCOFF("answer"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if err := run([]string{"objcopy", "-wrap", "answer", input}, &stdout, &stderr); err == nil || exitCode(err) != 2 {
		t.Fatalf("objcopy without output: %v", err)
	}
	out := filepath.Join(dir, "x.obj")
	if err := run([]string{"objcopy", "-weaken-symbol", "answer", input, out}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "weakening is unsupported for COFF") {
		t.Fatalf("objcopy -weaken-symbol of COFF: %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("objcopy wrote an output after failing")
	}
	// A Windows build applies the edits and translates the result.
	err := run([]string{"build", "-target", "windows/amd64", "-redefine-sym", "answer=renamed", "-symbol", "renamed", "-o", filepath.Join(dir, "pkg"), input}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("build: %v\n%s", err, stderr.String())
	}
	record, err := os.ReadFile(filepath.Join(dir, "pkg", "bao-build.json"))
	if err != nil || !strings.Contains(string(record), `"answer": "renamed"`) {
		t.Fatalf("bao-build.json: %v\n%s", err, record)
	}
}
