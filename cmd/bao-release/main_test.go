package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseMetadata(t *testing.T) {
	o := options{version: "v1.2.3-rc.1+build.4", commit: strings.Repeat("a", 40), epoch: 1770000000, stage: "stage", out: "out"}
	if err := validate(o); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"1.2.3", "v01.2.3", "v1.2.3-01", "v1.2.3/../../bad", "v1.2.3\nINJECT=1", "v1.2.3-"} {
		o.version = tag
		if validate(o) == nil {
			t.Fatalf("accepted %q", tag)
		}
	}
}

func TestDeterministicArchiveAndLicenses(t *testing.T) {
	common := map[string][]byte{"LICENSE": []byte("Bao license"), "licenses/LICENSE-GO.txt": []byte("Go license"), "licenses/LICENSE-PUREGO.txt": []byte("purego license")}
	stamp := time.Unix(1770000000, 0).UTC()
	a, err := archive("bao_v1.2.3_linux_arm64", []byte("executable"), common, stamp)
	if err != nil {
		t.Fatal(err)
	}
	b, err := archive("bao_v1.2.3_linux_arm64", []byte("executable"), common, stamp)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("archive is not deterministic", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(stamp) {
			t.Fatal("non-normalized tar metadata")
		}
		if strings.HasSuffix(h.Name, "/bao") && h.Mode != 0o755 {
			t.Fatal("CLI is not executable")
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(h.Name, "bao_v1.2.3_linux_arm64/")
		if name != "bao" && !bytes.Equal(body, common[name]) {
			t.Fatal("lost license payload", name)
		}
		seen++
	}
	if seen != 4 {
		t.Fatalf("got %d files", seen)
	}
}

func TestWrongBinaryAndIncompleteMatrix(t *testing.T) {
	if checkBinary([]byte("not an executable"), "linux_arm64") == nil {
		t.Fatal("accepted garbage")
	}
	// A minimally parseable x86 ELF header must not enter the arm64 archive.
	b := make([]byte, 64)
	copy(b, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	if err := checkBinary(b, "linux_amd64"); err != nil {
		t.Fatal(err)
	}
	if checkBinary(b, "linux_arm64") == nil {
		t.Fatal("accepted wrong architecture")
	}
	root := t.TempDir()
	for _, name := range []string{"LICENSE", "bindings/bootstrap/LICENSE-GO.txt", "bindings/bootstrap/LICENSE-PUREGO.txt", "bindings/bootstrap/provenance.json"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("license"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(root, "out")
	if err := run(options{root: root, stage: root, out: out, version: "v1.2.3", commit: strings.Repeat("a", 40), epoch: 1770000000}); err == nil {
		t.Fatal("accepted missing binary matrix")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("incomplete release left output", err)
	}
}

func TestCompleteReleaseChecksumsAndNoOverwrite(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"LICENSE", "bindings/bootstrap/LICENSE-GO.txt", "bindings/bootstrap/LICENSE-PUREGO.txt", "bindings/bootstrap/provenance.json"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range targets {
		b := make([]byte, 64)
		if strings.HasPrefix(target, "darwin") {
			binary.LittleEndian.PutUint32(b, 0xfeedfacf)
			cpu := uint32(0x100000c)
			if target == "darwin_amd64" {
				cpu = 0x1000007
			}
			binary.LittleEndian.PutUint32(b[4:], cpu)
			binary.LittleEndian.PutUint32(b[12:], 2)
		} else {
			copy(b, "\x7fELF\x02\x01\x01")
			binary.LittleEndian.PutUint16(b[16:], 2)
			machine := map[string]uint16{"linux_amd64": 62, "linux_arm64": 183, "linux_loong64": 258, "linux_ppc64le": 21}[target]
			binary.LittleEndian.PutUint16(b[18:], machine)
			binary.LittleEndian.PutUint32(b[20:], 1)
			binary.LittleEndian.PutUint16(b[52:], 64)
		}
		dir := filepath.Join(root, target)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bao"), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	o := options{root: root, stage: root, out: filepath.Join(root, "out"), version: "v1.2.3", commit: strings.Repeat("a", 40), epoch: 1770000000}
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile(filepath.Join(o.out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected six archives plus metadata, got %d", len(lines))
	}
	for _, line := range lines {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatal("bad checksum format", line)
		}
		b, err := os.ReadFile(filepath.Join(o.out, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); digest != got {
			t.Fatal("checksum mismatch", name)
		}
	}
	if err := run(o); err == nil {
		t.Fatal("overwrote existing output")
	}
	after, err := os.ReadFile(filepath.Join(o.out, "SHA256SUMS"))
	if err != nil || !bytes.Equal(sums, after) {
		t.Fatal("existing release was damaged", err)
	}
}
