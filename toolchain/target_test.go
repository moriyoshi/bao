package toolchain

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rawObject(linux bool) []byte {
	if linux {
		b := make([]byte, 64)
		copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
		binary.LittleEndian.PutUint16(b[16:], 1)
		binary.LittleEndian.PutUint16(b[18:], 183)
		binary.LittleEndian.PutUint32(b[20:], 1)
		binary.LittleEndian.PutUint16(b[52:], 64)
		binary.LittleEndian.PutUint16(b[58:], 64)
		return b
	}
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x100000c)
	binary.LittleEndian.PutUint32(b[12:], 1)
	return b
}

func TestDetectTargetAndRejectMixedArchives(t *testing.T) {
	dir := t.TempDir()
	for _, linux := range []bool{false, true} {
		path := filepath.Join(dir, fmt.Sprintf("object-%v.o", linux))
		os.WriteFile(path, rawObject(linux), 0o644)
		target, archive, err := Detect(path)
		want := "darwin/arm64"
		if linux {
			want = "linux/arm64"
		}
		if err != nil || archive || target.Name != want {
			t.Fatalf("target=%+v archive=%v err=%v", target, archive, err)
		}
	}
	archive := []byte("!<arch>\n")
	for i, linux := range []bool{false, true} {
		object := rawObject(linux)
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", fmt.Sprintf("member%d.o/", i), 0, 0, 0, "644", len(object))
		archive = append(append(archive, header...), object...)
	}
	path := filepath.Join(dir, "mixed.a")
	os.WriteFile(path, archive, 0o644)
	if _, _, err := Detect(path); err == nil || !strings.Contains(err.Error(), "mixes") {
		t.Fatalf("mixed-ABI archive accepted: %v", err)
	}
	elf := rawObject(true)
	binary.LittleEndian.PutUint16(elf[18:], 62)
	os.WriteFile(path, elf, 0o644)
	if target, archive, err := Detect(path); err != nil || archive || target.Name != "linux/amd64" {
		t.Fatalf("x86 ELF target detection: %+v %v %v", target, archive, err)
	}
	binary.LittleEndian.PutUint16(elf[18:], 243) // RISC-V remains unsupported.
	os.WriteFile(path, elf, 0o644)
	if _, _, err := Detect(path); err == nil {
		t.Fatal("unsupported ELF machine accepted")
	}
}
