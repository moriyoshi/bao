// Package toolchain coordinates producer tools. Native translation itself stays
// in the platform backends and never invokes a compiler or linker.
package toolchain

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"github.com/moriyoshi/bao/internal/ar"
	"github.com/moriyoshi/bao/pecoff"
)

type Target struct {
	Name       string `json:"target"`
	RustTriple string `json:"rust_target"`
	Object     string `json:"native_object"`
}

func Targets() []Target {
	return []Target{
		{"darwin/arm64", "aarch64-apple-darwin", "Mach-O"},
		{"darwin/amd64", "x86_64-apple-darwin", "Mach-O"},
		{"linux/arm64", "aarch64-unknown-linux-gnu", "ELF (glibc)"},
		{"linux/amd64", "x86_64-unknown-linux-gnu", "ELF (glibc)"},
		{"linux/loong64", "loongarch64-unknown-linux-gnu", "ELF (glibc; experimental)"},
		{"linux/ppc64le", "powerpc64le-unknown-linux-gnu", "ELF (glibc; experimental)"},
		{"windows/amd64", "x86_64-pc-windows-gnu", "COFF"},
		{"windows/arm64", "aarch64-pc-windows-gnullvm", "COFF"},
	}
}

func ParseTarget(name string) (Target, error) {
	for _, t := range Targets() {
		if t.Name == name {
			return t, nil
		}
	}
	return Target{}, fmt.Errorf("unsupported target %q; run bao targets", name)
}

func HostTarget() (Target, error) { return ParseTarget(runtime.GOOS + "/" + runtime.GOARCH) }

// Detect checks every archive member before any producer tool executes. Member
// names remain metadata; they are never used as extraction destinations.
func Detect(path string) (target Target, archive bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return target, false, err
	}
	if bytes.HasPrefix(b, []byte("!<arch>\n")) {
		members, err := ar.ParseCOFF(b)
		if err != nil {
			return target, true, err
		}
		if len(members) == 0 {
			return target, true, fmt.Errorf("archive contains no object members")
		}
		for _, member := range members {
			t, err := detectObject(member.Data)
			if err != nil {
				return target, true, fmt.Errorf("archive member %q: %w", member.Name, err)
			}
			if target.Name != "" && t.Name != target.Name {
				return target, true, fmt.Errorf("archive mixes %s and %s objects", target.Name, t.Name)
			}
			target = t
		}
		return target, true, nil
	}
	if bytes.HasPrefix(b, []byte("!<thin>\n")) {
		return target, true, fmt.Errorf("thin archives are unsupported; supply an ordinary archive or combined object")
	}
	if bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
		// Linked shared objects are accepted as a whole input, never as
		// archive members.
		if f, err := elf.NewFile(bytes.NewReader(b)); err == nil && f.Type == elf.ET_DYN {
			f.Close()
			if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_AARCH64 {
				return target, false, fmt.Errorf("shared-object input supports little-endian ELF64 AArch64 (linux/arm64), got %s/%s", f.Class, f.Machine)
			}
			target, err = ParseTarget("linux/arm64")
			return target, false, err
		}
	}
	target, err = detectObject(b)
	return target, false, err
}

func detectObject(b []byte) (Target, error) {
	if len(b) >= 20 && binary.LittleEndian.Uint16(b) == 0x14c {
		return Target{}, fmt.Errorf("Windows/386 COFF is unsupported; Windows targets are amd64/arm64")
	}
	if m, err := pecoff.Machine(b); err == nil {
		if m == 0x8664 {
			return ParseTarget("windows/amd64")
		}
		return ParseTarget("windows/arm64")
	}
	if bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			return Target{}, err
		}
		defer f.Close()
		if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_REL {
			return Target{}, fmt.Errorf("requires little-endian ELF64 relocatable objects, got %s/%s/%s", f.Class, f.Machine, f.Type)
		}
		switch f.Machine {
		case elf.EM_AARCH64:
			return ParseTarget("linux/arm64")
		case elf.EM_X86_64:
			return ParseTarget("linux/amd64")
		case elf.EM_LOONGARCH:
			return ParseTarget("linux/loong64")
		case elf.EM_PPC64:
			return ParseTarget("linux/ppc64le")
		default:
			return Target{}, fmt.Errorf("unsupported ELF machine %s", f.Machine)
		}
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		return Target{}, fmt.Errorf("requires a Mach-O/ELF/COFF relocatable object or ordinary static archive: %w", err)
	}
	defer f.Close()
	if f.Cpu == macho.CpuAmd64 && f.SubCpu == 3 && f.Type == macho.TypeObj && f.Magic == macho.Magic64 {
		return ParseTarget("darwin/amd64")
	}
	if f.Cpu != macho.CpuArm64 || f.SubCpu != 0 || f.Type != macho.TypeObj || f.Magic != macho.Magic64 {
		return Target{}, fmt.Errorf("requires macOS arm64 Mach-O objects (arm64e, fat and executable inputs are unsupported)")
	}
	return ParseTarget("darwin/arm64")
}
