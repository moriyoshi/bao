package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A leaf C ABI function returning 42, encoded as an ordinary AMD64 COFF object.
// These producer/provenance tests require no external compiler or linker.
func staticLeafCOFF(name string) []byte {
	// debug/pe probes a 96-byte DOS header even for ordinary COFF inputs.
	data := make([]byte, 96)
	binary.LittleEndian.PutUint16(data, 0x8664)
	binary.LittleEndian.PutUint16(data[2:], 1)
	binary.LittleEndian.PutUint32(data[8:], 66)
	binary.LittleEndian.PutUint32(data[12:], 1)
	copy(data[20:], ".text")
	binary.LittleEndian.PutUint32(data[36:], 6)
	binary.LittleEndian.PutUint32(data[40:], 60)
	binary.LittleEndian.PutUint32(data[56:], 0x60500020)
	copy(data[60:], []byte{0xb8, 42, 0, 0, 0, 0xc3})
	copy(data[66:74], name)
	binary.LittleEndian.PutUint16(data[78:], 1)
	binary.LittleEndian.PutUint16(data[80:], 0x20)
	data[82] = 2
	binary.LittleEndian.PutUint32(data[84:], 4)
	return data
}

func writeStaticArchive(t *testing.T, path, name string) []byte {
	t.Helper()
	object := staticLeafCOFF(name)
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", "leaf.obj/", 0, 0, 0, "644", len(object))
	data := append([]byte("!<arch>\n"+header), object...)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildAndTranslatePublishCOFF(t *testing.T) {
	for _, command := range []string{"build", "translate"} {
		for _, mode := range []string{"runtime", "generated"} {
			t.Run(command+"-"+mode, func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "leaf.obj")
				original := staticLeafCOFF("answer")
				if err := os.WriteFile(input, original, 0644); err != nil {
					t.Fatal(err)
				}
				manifest := filepath.Join(dir, "signatures.json")
				if err := os.WriteFile(manifest, []byte(`{"schema":1,"abi":"c","functions":[{"name":"Answer","symbol":"answer","params":[],"result":"uint64"}]}`), 0644); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(dir, "native package")
				args := []string{command, "-target", "windows/amd64", "-symbol", "answer", "-o", output}
				if mode == "generated" {
					args = append(args, "-bindings", manifest)
				}
				args = append(args, input)
				var stdout, stderr strings.Builder
				if err := run(args, &stdout, &stderr); err != nil {
					t.Fatalf("publication failed: %v %s", err, stderr.String())
				}
				for _, name := range []string{"bao-manifest.json", "symbols_windows_amd64.go", "native_0_windows_amd64.syso"} {
					if _, err := os.Stat(filepath.Join(output, name)); err != nil {
						t.Fatal("missing published artifact", name, err)
					}
				}
				if mode == "generated" {
					if _, err := os.Stat(filepath.Join(output, "bao-bindings.json")); err != nil {
						t.Fatal("missing generated bindings", err)
					}
				}
				if b, err := os.ReadFile(input); err != nil || !bytes.Equal(b, original) {
					t.Fatal("publication changed the input", err)
				}
				if matches, err := filepath.Glob(filepath.Join(dir, ".bao-*")); err != nil || len(matches) != 0 {
					t.Fatalf("publication retained staging: %v %v", matches, err)
				}
			})
		}
	}
}

func TestBuildRepeatedDependencyArchivesAndNoticeProvenance(t *testing.T) {
	dir := t.TempDir()
	primary, one, two := filepath.Join(dir, "primary.a"), filepath.Join(dir, "dependency one.a"), filepath.Join(dir, "-dependency two.a")
	originals := map[string][]byte{primary: writeStaticArchive(t, primary, "answer"), one: writeStaticArchive(t, one, "unused1"), two: writeStaticArchive(t, two, "unused2")}
	noticeOne, noticeTwo := filepath.Join(dir, "COPYRIGHT"), filepath.Join(dir, "other-COPYRIGHT")
	for path, data := range map[string][]byte{noticeOne: []byte("Runtime notice one\r\nAll rights as stated.\r\n"), noticeTwo: []byte("Runtime notice two\nLiteral $ and tabs\tretained.\n")} {
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
		originals[path] = data
	}
	output := filepath.Join(dir, "native")
	var stdout, stderr strings.Builder
	err := run([]string{"build", "-target", "windows/amd64", "-symbol", "answer", "-link-archive", one, "-link-archive", two, "-link-notice", noticeOne, "-link-notice", noticeTwo, "-o", output, primary}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("build: %v; %s", err, stderr.String())
	}
	var provenance struct {
		SourceSHA256   string                                    `json:"source_sha256"`
		LinkedArchives []struct{ Path, SHA256 string }           `json:"linked_archives"`
		LinkedNotices  []struct{ Path, SHA256, Artifact string } `json:"linked_notices"`
	}
	data, err := os.ReadFile(filepath.Join(output, "bao-build.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.SourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(originals[primary])) || len(provenance.LinkedArchives) != 2 || len(provenance.LinkedNotices) != 2 {
		t.Fatalf("incomplete provenance: %+v", provenance)
	}
	for i, path := range []string{one, two} {
		entry := provenance.LinkedArchives[i]
		if entry.Path != path || entry.SHA256 != fmt.Sprintf("%x", sha256.Sum256(originals[path])) {
			t.Fatalf("archive order/digest lost: %+v", entry)
		}
	}
	for i, path := range []string{noticeOne, noticeTwo} {
		entry := provenance.LinkedNotices[i]
		retained, err := os.ReadFile(filepath.Join(output, entry.Artifact))
		if err != nil || !bytes.Equal(retained, originals[path]) || entry.Path != path || entry.SHA256 != fmt.Sprintf("%x", sha256.Sum256(retained)) || entry.Artifact != fmt.Sprintf("bao-linked-license-%d.txt", i) {
			t.Fatalf("notice order/bytes/digest lost: %+v %v", entry, err)
		}
	}
	for path, original := range originals {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, original) {
			t.Fatalf("producer changed source: %s %v", path, err)
		}
	}
}

func TestMissingLinkedNoticeDoesNotPublishOrRetainScratch(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary.a")
	writeStaticArchive(t, primary, "answer")
	output := filepath.Join(dir, "native")
	var stdout, stderr strings.Builder
	err := run([]string{"build", "-target", "windows/amd64", "-symbol", "answer", "-link-notice", filepath.Join(dir, "missing-notice"), "-o", output, primary}, &stdout, &stderr)
	if err == nil {
		t.Fatal("missing explicit notice silently accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed notice retention published output")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".bao-build-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("failed build retained scratch: %v %v", matches, err)
	}
}

func TestFinalizeRuntimeBindingIsRejectedBeforeOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "primary.a")
	writeStaticArchive(t, input, "answer")
	manifest := filepath.Join(dir, "signatures.json")
	if err := os.WriteFile(manifest, []byte(`{"schema":1,"abi":"c","functions":[{"name":"FinalizeRuntime","symbol":"answer","result":"uint64"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "native")
	var stdout, stderr strings.Builder
	err := run([]string{"build", "-target", "windows/amd64", "-bindings", manifest, "-o", output, input}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("runtime API binding collision accepted: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("binding collision published output")
	}
}

// importingCOFF defines answer, which calls the undefined MaybeMissing.
func importingCOFF() []byte {
	data := make([]byte, 112)
	binary.LittleEndian.PutUint16(data, 0x8664)
	binary.LittleEndian.PutUint16(data[2:], 1)
	binary.LittleEndian.PutUint32(data[8:], 76)
	binary.LittleEndian.PutUint32(data[12:], 2)
	copy(data[20:], ".text")
	binary.LittleEndian.PutUint32(data[36:], 6)
	binary.LittleEndian.PutUint32(data[40:], 60)
	binary.LittleEndian.PutUint32(data[44:], 66)
	binary.LittleEndian.PutUint16(data[52:], 1)
	binary.LittleEndian.PutUint32(data[56:], 0x60500020)
	copy(data[60:], []byte{0xe8, 0, 0, 0, 0, 0xc3})
	binary.LittleEndian.PutUint32(data[66:], 1)
	binary.LittleEndian.PutUint32(data[70:], 1)
	binary.LittleEndian.PutUint16(data[74:], 4)
	copy(data[76:84], "answer")
	binary.LittleEndian.PutUint16(data[88:], 1)
	binary.LittleEndian.PutUint16(data[90:], 0x20)
	data[92] = 2
	binary.LittleEndian.PutUint32(data[98:], 4)
	data[110] = 2
	strings := append(binary.LittleEndian.AppendUint32(nil, 17), "MaybeMissing\x00"...)
	return append(data, strings...)
}

func TestWindowsFunctionImportsResolveAtCallTime(t *testing.T) {
	dir := t.TempDir()
	o := importingCOFF()
	input := filepath.Join(dir, "leaf.obj")
	if err := os.WriteFile(input, o, 0644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "native")
	var stdout, stderr strings.Builder
	if err := run([]string{"translate", "-target", "windows/amd64", "-symbol", "answer", "-windows-import", "MaybeMissing=optional.dll", "-o", output, input}, &stdout, &stderr); err != nil {
		t.Fatalf("%v %s", err, stderr.String())
	}
	source, err := os.ReadFile(filepath.Join(output, "symbols_windows_amd64.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, `baoResolveImport("optional.dll", "MaybeMissing")`) {
		t.Fatalf("import is not resolved through the fallback:\n%s", text)
	}
	if strings.Contains(text, `NewProc("MaybeMissing").Addr()`) {
		t.Fatal("function import is still resolved eagerly")
	}
	for _, want := range []string{"proc.Find() == nil", "syscall.NewCallback", "is unavailable on this system", "syscall.Exit(2)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated fallback lacks %q", want)
		}
	}
}
