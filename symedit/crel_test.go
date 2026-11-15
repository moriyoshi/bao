package symedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"
)

// toCREL rewrites an object's RELA sections as CREL sections at the end of
// the file, as clang -Wa,--crel would have written them.
func toCREL(t *testing.T, data []byte) []byte {
	t.Helper()
	out := bytes.Clone(data)
	shoff := binary.LittleEndian.Uint64(out[0x28:])
	for i := 0; i < int(binary.LittleEndian.Uint16(out[0x3c:])); i++ {
		h := out[shoff+uint64(i)*sectionHeaderSize:]
		if elf.SectionType(binary.LittleEndian.Uint32(h[4:])) != elf.SHT_RELA {
			continue
		}
		off, size := binary.LittleEndian.Uint64(h[24:]), binary.LittleEndian.Uint64(h[32:])
		encoded := encodeCREL(data[off:off+size], true)
		binary.LittleEndian.PutUint32(h[4:], uint32(shtCREL))
		binary.LittleEndian.PutUint64(h[24:], uint64(len(out)))
		binary.LittleEndian.PutUint64(h[32:], uint64(len(encoded)))
		binary.LittleEndian.PutUint64(h[56:], 0)
		out = append(out, encoded...)
	}
	return out
}

// relocations returns each relocation section's entries as RELA, decoding
// CREL ones.
func relocations(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	f, err := parseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for i, s := range f.sections {
		switch s.typ {
		case elf.SHT_RELA:
			out[f.sections[s.info].name] = bytes.Clone(f.section(i))
		case shtCREL:
			entries, _, err := decodeCREL(f.section(i))
			if err != nil {
				t.Fatal(err)
			}
			out[f.sections[s.info].name] = entries
		}
	}
	return out
}

func TestCRELRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, addend := range []bool{true, false} {
		var entries []byte
		offset := uint64(0)
		for i := 0; i < 200; i++ {
			// Deltas from 0 to beyond one ULEB128 byte, and negative symbol,
			// type and addend deltas.
			offset += uint64(r.Intn(4)) << uint(r.Intn(12))
			a := uint64(0)
			if addend {
				a = uint64(r.Int63n(1<<40) - 1<<39)
			}
			entries = binary.LittleEndian.AppendUint64(entries, offset&^3)
			entries = binary.LittleEndian.AppendUint64(entries, uint64(r.Intn(300))<<32|uint64(r.Intn(40)))
			entries = binary.LittleEndian.AppendUint64(entries, a)
		}
		decoded, gotAddend, err := decodeCREL(encodeCREL(entries, addend))
		if err != nil || gotAddend != addend || !bytes.Equal(decoded, entries) {
			t.Fatalf("addend %v: round trip failed: %v", addend, err)
		}
	}
	for _, bad := range [][]byte{nil, {0x80}, {8 * 3}, {8 | 4, 0x80}} {
		if _, _, err := decodeCREL(bad); err == nil {
			t.Errorf("decodeCREL(%x) succeeded", bad)
		}
	}
}

// Edits give the same relocations whether the input stores them as RELA or
// CREL.
func TestCRELEditsMatchRELA(t *testing.T) {
	for name, e := range map[string]Edits{
		"wrap":            {Wrap: []string{"foo", "bar"}},
		"localize, strip": {Visibility: Visibility{Localize: matcher(t, false, "foo"), StripUnneeded: true}},
		"remove section":  {RemoveSection: matcher(t, false, ".debug_info")},
		"add symbol":      {AddSymbols: []AddedSymbol{{Name: "alias", Section: ".text", Bind: elf.STB_LOCAL, Type: elf.STT_FUNC}}},
	} {
		for _, in := range [][]byte{fixture(), sectionFixture()} {
			rela, _, err := Edit(in, e)
			if err != nil {
				t.Fatalf("%s: RELA: %v", name, err)
			}
			crel, _, err := Edit(toCREL(t, in), e)
			if err != nil {
				t.Fatalf("%s: CREL: %v", name, err)
			}
			if got, want := relocations(t, crel), relocations(t, rela); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: CREL relocations differ from RELA", name)
			}
			_, _, _, gotSyms := layout(t, crel)
			_, _, _, wantSyms := layout(t, rela)
			if !reflect.DeepEqual(gotSyms, wantSyms) {
				t.Errorf("%s: symbols %q, want %q", name, gotSyms, wantSyms)
			}
		}
	}
}
