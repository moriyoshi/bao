package toolchain

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func staticArchiveFixture(t *testing.T, path string, objects ...[]byte) {
	t.Helper()
	var data bytes.Buffer
	data.WriteString("!<arch>\n")
	for i, object := range objects {
		fmt.Fprintf(&data, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", fmt.Sprintf("m%d.o/", i), 0, 0, 0, "644", len(object))
		data.Write(object)
		if len(object)%2 != 0 {
			data.WriteByte('\n')
		}
	}
	if err := os.WriteFile(path, data.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func staticCOFFHeader(machine uint16) []byte {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint16(data, machine)
	return data
}

func TestStaticArchiveSearchKeepsPrimaryWholeAndDependenciesGrouped(t *testing.T) {
	dir := t.TempDir()
	input, one, two := filepath.Join(dir, "primary.a"), filepath.Join(dir, "-dep one.a"), filepath.Join(dir, "dep $(literal).a")
	for _, path := range []string{input, one, two} {
		staticArchiveFixture(t, path, rawObject(true))
	}
	target, _ := ParseTarget("linux/arm64")
	output := filepath.Join(dir, "combined.o")
	var commands []Command
	err := CombineWithArchives(context.Background(), func(_ context.Context, c Command) ([]byte, error) { commands = append(commands, c); return nil, nil }, target, "chosen-ld", "", "", input, output, []string{one, two, one})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-r", "--whole-archive", input, "--no-whole-archive", "--start-group", one, two, one, "--end-group", "-o", output}
	if len(commands) != 1 || commands[0].Tool != "chosen-ld" || !reflect.DeepEqual(commands[0].Args, want) {
		t.Fatalf("dependency order/multiplicity or archive search semantics changed: %+v", commands)
	}
}

func TestDarwinDependencyArchivesAreSearchedRatherThanForceLoaded(t *testing.T) {
	dir := t.TempDir()
	sdk := filepath.Join(dir, "sdk")
	if err := os.Mkdir(sdk, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "SDKSettings.json"), []byte(`{"Version":"26.5"}`), 0644); err != nil {
		t.Fatal(err)
	}
	input, dep := filepath.Join(dir, "primary.a"), filepath.Join(dir, "dependency.a")
	staticArchiveFixture(t, input, rawObject(false))
	staticArchiveFixture(t, dep, rawObject(false))
	target, _ := ParseTarget("darwin/arm64")
	var command Command
	err := CombineWithArchives(context.Background(), func(_ context.Context, c Command) ([]byte, error) { command = c; return nil, nil }, target, "chosen-ld", sdk, "11.0", input, filepath.Join(dir, "combined.o"), []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-r", "-arch", "arm64", "-platform_version", "macos", "11.0", "26.5", "-force_load", input, dep, "-o", filepath.Join(dir, "combined.o")}
	if !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("dependency became whole-loaded or literal path changed: %+v", command)
	}
}

func TestInvalidStaticDependenciesFailBeforeProducerOrOutput(t *testing.T) {
	for _, name := range []string{"linux/arm64", "darwin/arm64", "windows/amd64"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target, _ := ParseTarget(name)
			object, wrong := rawObject(true), rawObject(false)
			if name == "darwin/arm64" {
				object, wrong = wrong, object
			}
			if name == "windows/amd64" {
				object, wrong = staticCOFFHeader(0x8664), staticCOFFHeader(0xaa64)
			}
			primary := filepath.Join(dir, "primary.a")
			staticArchiveFixture(t, primary, object)
			raw, mismatch, mixed, malformed := filepath.Join(dir, "object.o"), filepath.Join(dir, "wrong.a"), filepath.Join(dir, "mixed.a"), filepath.Join(dir, "not-an-archive.a")
			if err := os.WriteFile(raw, object, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(malformed, []byte("not native input"), 0644); err != nil {
				t.Fatal(err)
			}
			staticArchiveFixture(t, mismatch, wrong)
			staticArchiveFixture(t, mixed, object, wrong)
			for _, dep := range []string{raw, mismatch, mixed, malformed} {
				output := filepath.Join(dir, "must-not-exist.o")
				calls := 0
				err := CombineWithArchives(context.Background(), func(context.Context, Command) ([]byte, error) { calls++; return nil, nil }, target, "unused-linker", "", "11.0", primary, output, []string{dep})
				if err == nil || calls != 0 {
					t.Fatalf("invalid dependency accepted or executed a producer: %s calls=%d err=%v", dep, calls, err)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("invalid dependency produced output: %s", dep)
				}
			}
		})
	}
}
