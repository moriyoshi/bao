package pecoff

import (
	"debug/pe"
	"encoding/binary"
	"strings"
	"testing"
)

func relativeFixture() *object {
	o := fixture(pe.IMAGE_FILE_MACHINE_ARM64)
	flags := uint32(pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | 0x400000)
	o.sections = append(o.sections, section{name: ".rdata", flags: flags, size: 4, data: []byte{0, 0, 0, 0}, relocs: []pe.Reloc{{Type: 17, SymbolTableIndex: 1}}}, section{name: ".rdata", flags: flags, size: 8, data: []byte("target\x00\x00")})
	o.addSymbol("target", 3, 0)
	return o
}
func TestARM64ConstantRelativeData(t *testing.T) {
	o := relativeFixture()
	o.sections[1].size = 8
	o.sections[1].data = append(o.sections[1].data, 0, 0, 0, 0)
	o.sections[1].relocs = append(o.sections[1].relocs, pe.Reloc{Type: 2, SymbolTableIndex: 0, VirtualAddress: 4})
	if err := o.lowerReadOnlyREL32(); err != nil {
		t.Fatal(err)
	}
	if o.symbols[1].SectionNumber != 2 || o.symbols[1].Value != 8 || int32(binary.LittleEndian.Uint32(o.sections[1].data)) != 4 {
		t.Fatal("relative pointer lost its displacement")
	}
	if len(o.sections[1].relocs) != 1 || o.sections[1].relocs[0].Type != 2 || string(o.sections[1].data[8:]) != "target\x00\x00" {
		t.Fatal("non-relative relocation or target data was lost")
	}
	if o.sections[2].size != 0 || o.sections[1].flags>>20&15 != 4 {
		t.Fatal("data alignment/section identity was lost")
	}
}
func TestARM64RelativeDataRejectsUnsupportedTargets(t *testing.T) {
	for name, mutate := range map[string]func(*object){
		"external":      func(o *object) { o.symbols[1].SectionNumber = 0 },
		"code":          func(o *object) { o.symbols[1].SectionNumber = 1 },
		"writable":      func(o *object) { o.sections[2].flags |= pe.IMAGE_SCN_MEM_WRITE },
		"site bounds":   func(o *object) { o.sections[1].relocs[0].VirtualAddress = 1 },
		"symbol bounds": func(o *object) { o.sections[1].relocs[0].SymbolTableIndex = 999 },
		"overflow":      func(o *object) { binary.LittleEndian.PutUint32(o.sections[1].data, 0x7fffffff) },
		"alignment":     func(o *object) { o.sections[2].flags = o.sections[2].flags&^0xf00000 | 0x700000 },
	} {
		t.Run(name, func(t *testing.T) {
			o := relativeFixture()
			mutate(o)
			if err := o.lowerReadOnlyREL32(); err == nil {
				t.Fatal("unsupported relative data accepted")
			}
		})
	}
}
func TestRuntimeFallbackKeepsInternalReferencesLocal(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections[0].relocs = []pe.Reloc{{Type: 4, SymbolTableIndex: 0}}
	localizeRuntimeFallbacks(o, map[string]int{"example": 9})
	if o.symbols[0].StorageClass != 3 || o.sections[0].relocs[0].SymbolTableIndex != 0 {
		t.Fatal("fallback shadowing lost its private definition")
	}
}
func TestImportLibraryThunkCannotBeNativeInput(t *testing.T) {
	o := fixture(pe.IMAGE_FILE_MACHINE_AMD64)
	o.sections[0].name = ".idata$5"
	_, err := parse(encoded(t, o))
	if err == nil || !strings.Contains(err.Error(), "import-library") {
		t.Fatalf("accepted import metadata: %v", err)
	}
}
