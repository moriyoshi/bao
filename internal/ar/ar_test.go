package ar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestCOFFNativePlaneRequiresExplicitECMap(t *testing.T) {
	native, ec := make([]byte, 20), make([]byte, 20)
	binary.LittleEndian.PutUint16(native, 0xaa64)
	binary.LittleEndian.PutUint16(ec, 0xa641)
	for _, ecMap := range []bool{false, true} {
		b := []byte("!<arch>\n")
		if ecMap {
			b = append(b, member("/<ECSYMBOLS>/", []byte{0, 0, 0, 0})...)
		}
		b = append(b, member("native.obj/", native)...)
		b = append(b, member("ec.obj/", ec)...)
		all, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 2 {
			t.Fatal("generic view dropped a regular member")
		}
		selected, err := ParseCOFF(b)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if ecMap {
			want = 1
		}
		if len(selected) != want || selected[0].Name != "native.obj" {
			t.Fatal("COFF native-plane selection mismatch")
		}
	}
}

func member(name string, data []byte) []byte {
	h := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
	b := append([]byte(h), data...)
	if len(data)%2 != 0 {
		b = append(b, '\n')
	}
	return b
}

func TestBSDAndGNUArchives(t *testing.T) {
	bsd := []byte("!<arch>\n")
	bsd = append(bsd, member("#1/12", append([]byte("__.SYMDEF\x00\x00\x00"), 1, 2))...)
	bsd = append(bsd, member("#1/20", append([]byte("long member name.o\x00\x00"), 3, 4, 5))...)
	gnu := []byte("!<arch>\n")
	gnu = append(gnu, member("/", []byte{1, 2})...)
	gnu = append(gnu, member("//", []byte("long member name.o/\n"))...)
	gnu = append(gnu, member("/0", []byte{3, 4, 5})...)
	for name, b := range map[string][]byte{"BSD": bsd, "GNU": gnu} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Name != "long member name.o" || !bytes.Equal(got[0].Data, []byte{3, 4, 5}) {
				t.Fatalf("unexpected members: %#v", got)
			}
		})
	}
}

func TestMalformedArchives(t *testing.T) {
	valid := append([]byte("!<arch>\n"), member("hello.o/", []byte{1})...)
	for _, b := range [][]byte{
		[]byte("!<thin>\n"), []byte("!<arch>\nx"), valid[:len(valid)-1],
		append([]byte("!<arch>\n"), member("#1/99", []byte{1, 2})...),
		append([]byte("!<arch>\n"), member("/0", nil)...),
		[]byte("!<arch>\n" + strings.Repeat("0", 60)),
	} {
		if _, err := Parse(b); err == nil {
			t.Fatalf("accepted malformed archive %q", b)
		}
	}
}

func TestMemberNamesAreMetadata(t *testing.T) {
	b := append([]byte("!<arch>\n"), member("../escape.o/", []byte{1, 2})...)
	members, err := Parse(b)
	if err != nil || len(members) != 1 || members[0].Name != "../escape.o" {
		t.Fatalf("parse: %v %v", members, err)
	}
}

func TestObjectViewFiltersBookkeepingAndPreservesDuplicates(t *testing.T) {
	b := []byte("!<arch>\n")
	for _, name := range []string{"/", "/SYM64/", "__.SYMDEF", "__.SYMDEF_64"} {
		b = append(b, member(name, []byte{1, 2})...)
	}
	b = append(b, member("//", []byte("same object.o/\n"))...)
	b = append(b, member("/0", []byte{3})...)
	b = append(b, member("/0", []byte{4})...)
	b = append(b, member("__.PKGDEF", []byte{5, 6})...)
	got, err := Parse(b)
	if err != nil || len(got) != 3 || got[0].Name != "same object.o" || got[1].Name != got[0].Name || got[0].Data[0] != 3 || got[1].Data[0] != 4 || got[2].Name != "__.PKGDEF" {
		t.Fatalf("object view changed: %+v %v", got, err)
	}
}

func TestCOFFExplicitNativeArchitectureAndImportMetadata(t *testing.T) {
	arm, amd, thunk := make([]byte, 20), make([]byte, 20), make([]byte, 60)
	binary.LittleEndian.PutUint16(arm, 0xaa64)
	binary.LittleEndian.PutUint16(amd, 0x8664)
	binary.LittleEndian.PutUint16(thunk, 0xaa64)
	binary.LittleEndian.PutUint16(thunk[2:], 1)
	copy(thunk[20:], ".idata$5")
	short := make([]byte, 20)
	binary.LittleEndian.PutUint16(short[2:], 0xffff)
	binary.LittleEndian.PutUint16(short[6:], 0xaa64)
	payload := []byte("function\x00ucrtbase.dll\x00")
	binary.LittleEndian.PutUint32(short[12:], uint32(len(payload)))
	short = append(short, payload...)
	for _, ecMap := range []bool{false, true} {
		b := []byte("!<arch>\n")
		if ecMap {
			b = append(b, member("/<ECSYMBOLS>/", nil)...)
		}
		for _, m := range []Member{{Name: "arm.obj/", Data: arm}, {Name: "amd.obj/", Data: amd}, {Name: "short.obj/", Data: short}, {Name: "thunk.obj/", Data: thunk}} {
			b = append(b, member(m.Name, m.Data)...)
		}
		all, err := Parse(b)
		if err != nil || len(all) != 4 {
			t.Fatalf("generic archive view: %v %v", all, err)
		}
		got, err := ParseCOFFForMachine(b, 0xaa64)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if ecMap {
			want = 1
		}
		if len(got) != want || got[0].Name != "arm.obj" {
			t.Fatalf("native view: %v", got)
		}
	}
	b := append([]byte("!<arch>\n"), member("import.obj/", short)...)
	got, err := ParseCOFFForMachine(b, 0xaa64)
	if err != nil || len(got) != 0 {
		t.Fatalf("import-only archive became native code: %v %v", got, err)
	}
	short[12] = 255 // Malformed records are retained for the caller to reject.
	b = append([]byte("!<arch>\n"), member("malformed.obj/", short)...)
	got, err = ParseCOFFForMachine(b, 0xaa64)
	if err != nil || len(got) != 1 {
		t.Fatalf("malformed input was silently discarded: %v %v", got, err)
	}
}

func TestCOFFPrimaryImportRecordsKeepMachineChecks(t *testing.T) {
	native, record := make([]byte, 20), make([]byte, 20)
	binary.LittleEndian.PutUint16(native, 0xaa64)
	binary.LittleEndian.PutUint16(record[2:], 0xffff)
	binary.LittleEndian.PutUint16(record[6:], 0xaa64)
	data := []byte("api\x00arbitrary.dll\x00")
	binary.LittleEndian.PutUint32(record[12:], uint32(len(data)))
	record = append(record, data...)
	build := func() []byte {
		b := append([]byte("!<arch>\n"), member("native.obj/", native)...)
		return append(b, member("imports.dll/", record)...)
	}
	got, err := ParseCOFF(build())
	if err != nil || len(got) != 1 {
		t.Fatalf("primary native view: %v %v", got, err)
	}
	all, err := Parse(build())
	if err != nil || len(all) != 2 {
		t.Fatal("generic/authentication view discarded import bytes")
	}
	binary.LittleEndian.PutUint16(record[6:], 0x8664)
	if _, err := ParseCOFF(build()); err == nil {
		t.Fatal("cross-architecture import declaration was hidden")
	}
}
