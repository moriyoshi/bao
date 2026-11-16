package build

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	o := Options{
		Input: "libglue.o", Output: "native", Target: "linux/arm64", Package: "pyembed", Sysroot: "/sysroot",
		Symbols: []string{"glue_run", "glue_stop"}, LinkArchives: []string{"liba.a"}, StripDebug: true,
		Wrap:            []string{"pthread_create", "pthread_join"},
		RedefineSymbols: map[string]string{"b": "b2", "a": "a2"},
		Linux:           LinuxOptions{SharedObject: "libpython3.13.so", MaxSymbolVersions: []string{"GLIBC_2.18"}, MaxTextAlignment: 4096, StaticTLS: true},
		Windows:         WindowsOptions{Imports: map[string]string{"Sleep": "kernel32.dll"}, DLL: "python313.dll"},
		Darwin:          DarwinOptions{Dylib: "libpython3.13.dylib"},
		Args:            []string{"-keep-global-symbol", "libglue.o=glue_*"},
	}
	want := []string{
		"-target", "linux/arm64", "-o", "native", "-package", "pyembed", "-sysroot", "/sysroot",
		"-symbol", "glue_run", "-symbol", "glue_stop", "-link-archive", "liba.a", "-strip-debug",
		"-wrap", "pthread_create", "-wrap", "pthread_join", "-redefine-sym", "a=a2", "-redefine-sym", "b=b2",
		"-linux-shared-object", "libpython3.13.so", "-linux-max-symbol-version", "GLIBC_2.18", "-linux-max-text-alignment", "4096", "-linux-static-tls",
		"-windows-import", "Sleep=kernel32.dll", "-windows-dll", "python313.dll", "-darwin-dylib", "libpython3.13.dylib", "-keep-global-symbol", "libglue.o=glue_*", "--", "libglue.o",
	}
	if got := o.CommandLine(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CommandLine =\n%q\nwant\n%q", got, want)
	}
}

// leafCOFF is an amd64 COFF object defining NAME, a function returning 42;
// a Windows build of it needs no native tools.
func leafCOFF(name string) []byte {
	data := make([]byte, 96) // debug/pe probes a 96-byte DOS header
	le := binary.LittleEndian
	le.PutUint16(data, 0x8664)
	le.PutUint16(data[2:], 1)
	le.PutUint32(data[8:], 66)
	le.PutUint32(data[12:], 1)
	copy(data[20:], ".text")
	le.PutUint32(data[36:], 6)
	le.PutUint32(data[40:], 60)
	le.PutUint32(data[56:], 0x60500020)
	copy(data[60:], []byte{0xb8, 42, 0, 0, 0, 0xc3})
	copy(data[66:74], name)
	le.PutUint16(data[78:], 1)
	le.PutUint16(data[80:], 0x20)
	data[82] = 2
	le.PutUint32(data[84:], 4)
	return data
}

// Run works more than once in one process, as a producer that builds one
// package per target does.
func TestRunTwice(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "leaf.obj")
	if err := os.WriteFile(input, leafCOFF("answer"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"windows/amd64", "windows/amd64"} {
		var stderr bytes.Buffer
		out := filepath.Join(t.TempDir(), "native")
		if err := Run(context.Background(), Options{Input: input, Output: out, Target: target, Symbols: []string{"answer"}, Stderr: &stderr}); err != nil {
			t.Fatalf("Run: %v\n%s", err, stderr.String())
		}
		files, err := filepath.Glob(filepath.Join(out, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no generated Go files in %s: %v", out, err)
		}
		provenance, err := os.ReadFile(filepath.Join(out, "bao-build.json"))
		if err != nil || !bytes.Contains(provenance, []byte(`"bao_version"`)) {
			t.Fatalf("bao-build.json: %v\n%s", err, provenance)
		}
	}
}

func TestRunErrors(t *testing.T) {
	if err := Run(context.Background(), Options{Output: "x"}); err == nil {
		t.Fatal("missing input accepted")
	}
	err := Run(context.Background(), Options{Input: "x.o", Output: filepath.Join(t.TempDir(), "o"), Args: []string{"-no-such-flag"}})
	if err == nil || !strings.Contains(err.Error(), "no-such-flag") {
		t.Fatalf("unknown flag: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Options{Input: "x.o", Output: "o"}); err == nil {
		t.Fatal("canceled context accepted")
	}
}
