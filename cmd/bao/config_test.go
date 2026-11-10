package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSignatures = `{"schema":1,"abi":"c","functions":[{"name":"Answer","symbol":"answer","params":[],"result":"uint64"}]}`

func configFlags(t *testing.T, name, body string, args ...string) (*nativeFlags, *flag.FlagSet, []string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bao.json")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	var o nativeFlags
	fs := newFlags(name, name, name)
	o.register(fs)
	if name == "build" {
		var archives, notices symbolFlags
		fs.Var(&archives, "link-archive", "")
		fs.Var(&notices, "link-notice", "")
		fs.Bool("require-static-runtime", false, "")
		fs.String("manifest-path", "", "")
		fs.String("cargo-package", "", "")
		fs.Bool("offline", false, "")
		fs.Bool("locked", false, "")
		fs.String("ld", "", "")
		fs.String("min-os", "11.0", "")
	}
	if err := fs.Parse(append([]string{"-config", path}, args...)); err != nil {
		t.Fatal(err)
	}
	positional, err := o.applyConfig(fs, io.Discard)
	return &o, fs, positional, err
}

func TestConfigSelectOnlyTheTargetSection(t *testing.T) {
	body := `{"schema":1,"package":"gen","symbols":["a","b"],"strip_debug":false,"strip_bitcode":false,
	"linux":{"sysroot":"/root","system_libraries":["libxcb.so.1"]},
	"windows":{"imports":{"Zed":"z.dll","Abc":"a.dll"},"cxx_runtime":"libc++","crt":"msvcrt","max_data_alignment":32}}`
	o, _, _, err := configFlags(t, "build", body, "-target", "windows/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if o.pkg != "gen" || o.stripDebug || o.stripBitcode || strings.Join(o.symbols, ",") != "a,b" {
		t.Fatalf("common config: %+v", o)
	}
	if strings.Join(o.windowsImports, ",") != "Abc=a.dll,Zed=z.dll" || o.windowsCXXRuntime != "libc++" || o.windowsCRT != "msvcrt" || o.windowsMaxDataAlignment != 32 {
		t.Fatalf("windows config: %+v", o)
	}
	if o.sysroot != "" || len(o.linuxSystemLibraries) != 0 {
		t.Fatalf("linux section leaked into windows: %+v", o)
	}
	o, _, _, err = configFlags(t, "build", body, "-target", "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if o.sysroot != "/root" || strings.Join(o.linuxSystemLibraries, ",") != "libxcb.so.1" || len(o.windowsImports) != 0 {
		t.Fatalf("linux config: %+v", o)
	}
}

func TestConfigCommandLineReplacesEachSetting(t *testing.T) {
	body := `{"schema":1,"package":"gen","symbols":["a","b"],"windows":{"crt":"msvcrt"}}`
	o, _, _, err := configFlags(t, "build", body, "-target", "windows/amd64", "-package", "cli", "-symbol", "c", "-windows-crt", "ucrt")
	if err != nil {
		t.Fatal(err)
	}
	if o.pkg != "cli" || strings.Join(o.symbols, ",") != "c" || o.windowsCRT != "ucrt" {
		t.Fatalf("%+v", o)
	}
}

func TestConfigPathsAndVariables(t *testing.T) {
	t.Setenv("BAO_TEST_PREFIX", "/opt/mingw")
	body := `{"schema":1,"input":"lib/native.a","link_archives":["dep/a.a","/abs/b.a"],
	"windows":{"import_libraries":["${BAO_TEST_PREFIX}/lib/libuser32.a"]}}`
	o, fs, positional, err := configFlags(t, "build", body, "-target", "windows/amd64")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(o.config)
	if len(positional) != 1 || positional[0] != filepath.Join(dir, "lib/native.a") {
		t.Fatalf("input %v", positional)
	}
	if got := fs.Lookup("link-archive").Value.String(); got != filepath.Join(dir, "dep/a.a")+",/abs/b.a" {
		t.Fatal(got)
	}
	if strings.Join(o.windowsImportLibraries, ",") != "/opt/mingw/lib/libuser32.a" {
		t.Fatalf("%v", o.windowsImportLibraries)
	}
	_, _, positional, err = configFlags(t, "build", body, "-target", "windows/amd64", "other.a")
	if err != nil || len(positional) != 1 || positional[0] != "other.a" {
		t.Fatalf("positional input must win: %v %v", positional, err)
	}
	_, _, _, err = configFlags(t, "build", `{"schema":1,"windows":{"import_libraries":["${BAO_TEST_UNSET}/x.a"]}}`, "-target", "windows/amd64")
	if err == nil || !strings.Contains(err.Error(), "BAO_TEST_UNSET is not set") {
		t.Fatalf("unset variable accepted: %v", err)
	}
}

func TestConfigPlatformLinkInputsFollowCommonOnes(t *testing.T) {
	body := `{"schema":1,"link_archives":["/common.a"],"require_static_runtime":false,
	"windows":{"link_archives":["/win.a"],"link_notices":["/win.txt"],"require_static_runtime":true}}`
	_, fs, _, err := configFlags(t, "build", body, "-target", "windows/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("link-archive").Value.String() != "/common.a,/win.a" || fs.Lookup("link-notice").Value.String() != "/win.txt" || fs.Lookup("require-static-runtime").Value.String() != "true" {
		t.Fatalf("%v %v %v", fs.Lookup("link-archive").Value, fs.Lookup("link-notice").Value, fs.Lookup("require-static-runtime").Value)
	}
	_, fs, _, err = configFlags(t, "build", body, "-target", "darwin/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if fs.Lookup("link-archive").Value.String() != "/common.a" || fs.Lookup("require-static-runtime").Value.String() != "false" {
		t.Fatalf("windows section leaked: %v", fs.Lookup("link-archive").Value)
	}
	_, fs, _, err = configFlags(t, "build", body, "-target", "windows/amd64", "-link-archive", "/cli.a")
	if err != nil || fs.Lookup("link-archive").Value.String() != "/cli.a" {
		t.Fatalf("flag must replace common and platform entries: %v %v", fs.Lookup("link-archive").Value, err)
	}
}

func TestConfigBindingForms(t *testing.T) {
	o, _, _, err := configFlags(t, "translate", `{"schema":1,"bindings":`+testSignatures+`}`)
	if err != nil || o.inlineBindings == nil || o.bindings != "" {
		t.Fatalf("inline: %+v %v", o, err)
	}
	if err := o.resolveBindings("", nil); err != nil || o.signatures == nil || o.symbols[0] != "answer" {
		t.Fatalf("inline resolved: %+v %v", o, err)
	}
	o, _, _, err = configFlags(t, "translate", `{"schema":1,"bindings":"dwarf"}`)
	if err != nil || o.bindings != "dwarf" {
		t.Fatalf("dwarf: %+v %v", o, err)
	}
	o, _, _, err = configFlags(t, "translate", `{"schema":1,"bindings":"sig.json"}`)
	if err != nil || o.bindings != filepath.Join(filepath.Dir(o.config), "sig.json") {
		t.Fatalf("path: %+v %v", o, err)
	}
	o, _, _, err = configFlags(t, "translate", `{"schema":1,"bindings":`+testSignatures+`}`, "-bindings", "cli.json")
	if err != nil || o.inlineBindings != nil || o.bindings != "cli.json" {
		t.Fatalf("flag must replace inline bindings: %+v %v", o, err)
	}
	o, _, _, err = configFlags(t, "translate", `{"schema":1,"bindings":{"schema":1,"abi":"c","functions":[{"name":"A","symbol":"a","params":[],"nope":1}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.resolveBindings("", nil); err == nil {
		t.Fatal("invalid inline bindings accepted")
	}
}

func TestConfigRejections(t *testing.T) {
	for _, tc := range []struct{ name, command, body, want string }{
		{"unknown key", "build", `{"schema":1,"nope":true}`, "nope"},
		{"duplicate key", "build", `{"schema":1,"package":"a","package":"b"}`, "duplicate"},
		{"schema", "build", `{"schema":2}`, "unsupported schema 2"},
		{"build-only key", "translate", `{"schema":1,"link_archives":["a.a"]}`, "does not apply to bao translate"},
		{"input and cargo", "build", `{"schema":1,"input":"a.a","cargo":{"manifest_path":"Cargo.toml"}}`, "not both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := configFlags(t, tc.command, tc.body, "-target", "windows/amd64")
			if err == nil || !strings.Contains(err.Error(), tc.want) || exitCode(err) != 2 {
				t.Fatalf("%v (exit %d)", err, exitCode(err))
			}
		})
	}
}

func TestConfigMatchEquivalentFlags(t *testing.T) {
	for _, command := range []string{"build", "translate"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "leaf.obj")
			if err := os.WriteFile(input, staticLeafCOFF("answer"), 0644); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(dir, "signatures.json")
			if err := os.WriteFile(manifest, []byte(testSignatures), 0644); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "bao.json")
			if err := os.WriteFile(config, []byte(`{"schema":1,"target":"windows/amd64","package":"gen","input":"leaf.obj","bindings":`+testSignatures+`}`), 0644); err != nil {
				t.Fatal(err)
			}
			flags, file := filepath.Join(dir, "flags"), filepath.Join(dir, "file")
			var stdout, stderr strings.Builder
			if err := run([]string{command, "-target", "windows/amd64", "-package", "gen", "-bindings", manifest, "-o", flags, input}, &stdout, &stderr); err != nil {
				t.Fatalf("flags: %v %s", err, stderr.String())
			}
			if err := run([]string{command, "-config", config, "-o", file}, &stdout, &stderr); err != nil {
				t.Fatalf("config: %v %s", err, stderr.String())
			}
			entries, err := os.ReadDir(flags)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				a, _ := os.ReadFile(filepath.Join(flags, entry.Name()))
				b, err := os.ReadFile(filepath.Join(file, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if entry.Name() != "bao-build.json" && !bytes.Equal(a, b) {
					t.Errorf("%s differs", entry.Name())
				}
			}
		})
	}
}

func TestDefaultConfigFile(t *testing.T) {
	apply := func(args ...string) (*nativeFlags, string, error) {
		var o nativeFlags
		fs := newFlags("build", "build", "build")
		o.register(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		var stderr strings.Builder
		_, err := o.applyConfig(fs, &stderr)
		return &o, stderr.String(), err
	}
	dir := t.TempDir()
	t.Chdir(dir)
	o, notice, err := apply("-target", "windows/amd64")
	if err != nil || o.pkg != "native" || notice != "" {
		t.Fatalf("no file: %+v %q %v", o, notice, err)
	}
	if err := os.WriteFile(defaultConfigFile, []byte(`{"schema":1,"package":"fromdefault"}`), 0644); err != nil {
		t.Fatal(err)
	}
	o, notice, err = apply("-target", "windows/amd64")
	if err != nil || o.pkg != "fromdefault" || !strings.Contains(notice, defaultConfigFile) {
		t.Fatalf("default: %+v %q %v", o, notice, err)
	}
	o, notice, err = apply("-config", "", "-target", "windows/amd64")
	if err != nil || o.pkg != "native" || notice != "" {
		t.Fatalf("opt-out: %+v %q %v", o, notice, err)
	}
	other := filepath.Join(dir, "other.json")
	if err := os.WriteFile(other, []byte(`{"schema":1,"package":"fromother"}`), 0644); err != nil {
		t.Fatal(err)
	}
	o, notice, err = apply("-config", other, "-target", "windows/amd64")
	if err != nil || o.pkg != "fromother" || notice != "" {
		t.Fatalf("explicit: %+v %q %v", o, notice, err)
	}
	if err := os.WriteFile(defaultConfigFile, []byte(`{"schema":1,"nope":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = apply("-target", "windows/amd64"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("invalid default file ignored: %v", err)
	}
}

func TestConfigTargetVariables(t *testing.T) {
	t.Setenv("BAO_PREFIX", "/opt/mingw")
	t.Setenv("BAO_GOARCH", "from-environment")
	body := `{"schema":1,"windows":{"import_libraries":["${BAO_PREFIX}/${BAO_CPU}-w64-mingw32/${BAO_GOOS}/${BAO_GOARCH}/libuser32.a"]}}`
	for _, tc := range []struct{ target, want string }{
		{"windows/amd64", "/opt/mingw/x86_64-w64-mingw32/windows/amd64/libuser32.a"},
		{"windows/arm64", "/opt/mingw/aarch64-w64-mingw32/windows/arm64/libuser32.a"},
	} {
		o, _, _, err := configFlags(t, "build", body, "-target", tc.target)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(o.windowsImportLibraries, ",") != tc.want {
			t.Fatalf("%s: %v", tc.target, o.windowsImportLibraries)
		}
	}
	_, _, _, err := configFlags(t, "build", `{"schema":1,"input":"${BAO_CPU}/lib.a"}`, "-target", "windows/amd64")
	if err == nil || !strings.Contains(err.Error(), "BAO_CPU is not available in input") {
		t.Fatalf("input must not use a target variable: %v", err)
	}
	_, _, _, err = configFlags(t, "build", `{"schema":1,"target":"plan9/amd64"}`)
	if err == nil || exitCode(err) != 2 {
		t.Fatalf("invalid target: %v", err)
	}
}
