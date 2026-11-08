package ar_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/ar"
)

func member(name string, data []byte) []byte {
	h := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
	b := append([]byte(h), data...)
	if len(data)%2 != 0 {
		b = append(b, '\n')
	}
	return b
}

func archive(parts ...[]byte) []byte {
	b := []byte("!<arch>\n")
	for _, part := range parts {
		b = append(b, part...)
	}
	return b
}

func bsd(name string, padding int, data []byte) []byte {
	n := append([]byte(name), make([]byte, padding)...)
	return member(fmt.Sprintf("#1/%d", len(n)), append(n, data...))
}

func field(b []byte, start, end int, value string) []byte {
	b = bytes.Clone(b)
	copy(b[start:end], strings.Repeat(" ", end-start))
	copy(b[start:end], value)
	return b
}

func TestAllRecordsAndNames(t *testing.T) {
	gnu := archive(
		member("/", []byte{1, 2}),
		member("/SYM64/", []byte{3, 4}),
		member("//", []byte("long member name.o/\n")),
		member("/0", []byte{5, 6, 7}),
		member("__.PKGDEF", nil),
	)
	got, err := ar.Parse(gnu)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"/", "/SYM64/", "//", "long member name.o", "__.PKGDEF"}
	wantKinds := []ar.Kind{ar.SymbolTable, ar.SymbolTable, ar.NameTable, ar.Regular, ar.Regular}
	if len(got) != len(wantNames) {
		t.Fatalf("lost archive records: %+v", got)
	}
	for i, m := range got {
		if m.Name != wantNames[i] || m.Kind != wantKinds[i] || m.Offset < 8 || (i > 0 && m.Offset <= got[i-1].Offset) {
			t.Fatalf("unexpected entry %d: %+v", i, m)
		}
	}
	if !bytes.Equal(got[0].Data, []byte{1, 2}) || !bytes.Equal(got[2].Data, []byte("long member name.o/\n")) || !bytes.Equal(got[3].Data, []byte{5, 6, 7}) {
		t.Fatal("bookkeeping or member payload changed")
	}
	got[2].Data[0] = 'X'
	if got[3].Name != "long member name.o" {
		t.Fatal("resolved string name changed with the borrowed name-table payload")
	}
	for _, name := range []string{"__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"} {
		b := archive(bsd(name, 3, []byte{1, 2}), member("file.o", []byte{3, 4}))
		got, err := ar.Parse(b)
		if err != nil || len(got) != 2 || got[0].Name != name || got[0].Kind != ar.SymbolTable || got[1].Name != "file.o" {
			t.Fatalf("BSD bookkeeping %q: %+v %v", name, got, err)
		}
	}
}

func TestBSDStoredSizeControlsPadding(t *testing.T) {
	for _, body := range [][]byte{{1, 2}, {1, 2, 3}} {
		for _, padding := range []int{0, 1, 2, 3} {
			first := bsd("a.o", padding, body)
			b := archive(first, member("next.o", []byte{4, 5}))
			got, err := ar.Parse(b)
			if err != nil || len(got) != 2 || got[0].Name != "a.o" || !bytes.Equal(got[0].Data, body) || got[1].Name != "next.o" || got[1].Offset != 8+len(first) {
				t.Fatalf("body %d/name pad %d: %+v %v", len(body), padding, got, err)
			}
		}
	}
}

func TestGNUNameReferencesAreByteOffsets(t *testing.T) {
	// Resolve exactly the supplied offset, including a suffix of an earlier name.
	b := archive(member("//", []byte("prefix-suffix.o/\n")), member("/7", []byte{1, 2}))
	got, err := ar.Parse(b)
	if err != nil || len(got) != 2 || got[1].Name != "suffix.o" {
		t.Fatalf("GNU byte offset: %+v %v", got, err)
	}
}

func TestDuplicatesBorrowingAndMetadataPaths(t *testing.T) {
	b := archive(member("../escape.o/", []byte{1}), member("../escape.o/", []byte{2}))
	// Go's archive packer uses NUL for an odd-sized member's padding.
	b[8+60+1] = 0
	before := bytes.Clone(b)
	got, err := ar.Parse(b)
	if err != nil || len(got) != 2 || got[0].Name != "../escape.o" || got[1].Name != got[0].Name || got[0].Offset != 8 || got[1].Offset != 70 {
		t.Fatalf("metadata/order/duplicates: %+v %v", got, err)
	}
	if !bytes.Equal(b, before) {
		t.Fatal("Parse changed its input")
	}
	if &got[0].Data[0] != &b[68] || cap(got[0].Data) != len(got[0].Data) {
		t.Fatal("payload is not a capacity-limited view of the input")
	}
	_ = append(got[0].Data, 99)
	if !bytes.Equal(b, before) {
		t.Fatal("appending a member overwrote archive framing")
	}
	got[0].Data[0] = 9
	if b[68] != 9 || got[1].Data[0] != 2 {
		t.Fatal("borrowing contract or member boundaries changed")
	}
	got, err = ar.Parse(archive(member(" leading.o", nil)))
	if err != nil || got[0].Name != " leading.o" {
		t.Fatal("a leading filename space was lost", got, err)
	}
}

func TestMalformedInputReturnsErrorsAndNoPartialResults(t *testing.T) {
	odd := member("one.o/", []byte{1})
	truncatedBody := member("one.o/", []byte{1, 2, 3, 4})
	table := member("//", []byte("first.o/\nsecond.o/\n"))
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"magic", []byte("other"), ar.ErrFormat},
		{"thin", []byte("!<thin>\n"), ar.ErrThinArchive},
		{"header", []byte("!<arch>\nx"), io.ErrUnexpectedEOF},
		{"trailer", archive(field(member("a.o", nil), 58, 60, "xx")), ar.ErrFormat},
		{"nonnumeric size", archive(field(member("a.o", nil), 48, 58, "abc")), ar.ErrFormat},
		{"negative size", archive(field(member("a.o", nil), 48, 58, "-1")), ar.ErrFormat},
		{"large size", archive(field(member("a.o", nil), 48, 58, "9999999999")), io.ErrUnexpectedEOF},
		{"short payload", archive(truncatedBody[:len(truncatedBody)-2]), io.ErrUnexpectedEOF},
		{"missing padding", archive(odd[:len(odd)-1]), io.ErrUnexpectedEOF},
		{"bad padding", archive(field(odd, 61, 62, "X")), ar.ErrFormat},
		{"BSD name exceeds member", archive(member("#1/4", []byte("ab"))), ar.ErrFormat},
		{"BSD negative name", archive(member("#1/-1", nil)), ar.ErrFormat},
		{"empty BSD name", archive(member("#1/0", nil)), ar.ErrFormat},
		{"empty short name", archive(member("", nil)), ar.ErrFormat},
		{"NUL in name", archive(bsd("a\x00b", 0, nil)), ar.ErrFormat},
		{"GNU missing table", archive(member("/0", nil)), ar.ErrFormat},
		{"GNU negative offset", archive(table, member("/-1", nil)), ar.ErrFormat},
		{"GNU offset at end", archive(table, member("/19", nil)), ar.ErrFormat},
		{"GNU empty entry", archive(member("//", []byte("\n")), member("/0", nil)), ar.ErrFormat},
		{"GNU no terminator", archive(member("//", []byte("name.o/")), member("/0", nil)), ar.ErrFormat},
		{"GNU duplicate table", archive(table, table), ar.ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ar.Parse(tc.data)
			var location *ar.ParseError
			if got != nil || !errors.Is(err, tc.want) || !errors.As(err, &location) || location.Offset < 0 || location.Offset > len(tc.data) {
				t.Fatalf("result=%+v error=%v location=%+v", got, err, location)
			}
		})
	}
	good := member("first.o", []byte{1, 2})
	got, err := ar.Parse(archive(good, field(member("bad.o", nil), 58, 60, "xx")))
	var location *ar.ParseError
	if got != nil || !errors.As(err, &location) || location.Offset != 8+len(good)+58 {
		t.Fatalf("partial result or wrong error offset: %+v %v", got, err)
	}
	if got, err := ar.Parse([]byte("!<arch>\n")); len(got) != 0 || err != nil {
		t.Fatal("empty archive rejected", got, err)
	}
}

func FuzzParse(f *testing.F) {
	for _, b := range [][]byte{
		{}, []byte("!<arch>\n"), []byte("!<thin>\n"),
		archive(member("a.o/", []byte{1})),
		archive(bsd("a.o", 0, []byte{1, 2}), member("next.o", nil)),
		archive(member("//", []byte("long-name.o/\n")), member("/0", nil)),
		archive(field(member("a.o", nil), 48, 58, "-1")),
		archive(member("//", []byte("\n")), member("/0", nil)),
	} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		members, err := ar.Parse(b)
		if err != nil {
			var location *ar.ParseError
			if members != nil || !errors.As(err, &location) || location.Offset < 0 || location.Offset > len(b) {
				t.Fatal("partial result or invalid error location")
			}
			return
		}
		previous := 0
		for _, m := range members {
			if m.Name == "" || m.Kind > ar.NameTable || m.Offset < 8 || m.Offset <= previous || m.Offset > len(b)-60 || len(m.Data) > len(b)-m.Offset-60 || cap(m.Data) != len(m.Data) {
				t.Fatal("invalid parsed member", m.Name, m.Offset)
			}
			previous = m.Offset
		}
	})
}

func TestCOFFNULTerminatedLongNames(t *testing.T) {
	table := member("//", []byte("path\\first object.obj\x00second object.obj\x00"))
	data := archive(table, member("/0", []byte{1}), member("/22", []byte{2}))
	got, err := ar.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].Name != "path\\first object.obj" || got[2].Name != "second object.obj" {
		t.Fatalf("COFF long names: %+v", got)
	}
	if _, err := ar.Parse(archive(member("//", []byte{0}), member("/0", nil))); err == nil {
		t.Fatal("empty COFF long name accepted")
	}
}

func TestCOFFECSymbolMapIsBookkeeping(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	got, err := ar.Parse(archive(member("/<ECSYMBOLS>/", payload), member("ordinary.obj/", []byte{7})))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Kind != ar.SymbolTable || got[0].Name != "/<ECSYMBOLS>/" || !bytes.Equal(got[0].Data, payload) || got[1].Kind != ar.Regular {
		t.Fatalf("EC symbol map: %+v", got)
	}
}
