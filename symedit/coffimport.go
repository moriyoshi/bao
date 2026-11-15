package symedit

import (
	"bytes"
	"errors"
	"fmt"
)

// coffImport is a short import member of an import library: a declaration
// that a DLL exports a function or data. It defines __imp_NAME, the import
// address table slot, and for code also NAME, a thunk the linker creates.
type coffImport struct {
	name, dll string
	data      bool
}

// isCOFFImport reports a short import member: IMPORT_OBJECT_HEADER has
// Sig1 0, Sig2 0xffff and version 0 or 1. A bigobj header has version 2.
func isCOFFImport(data []byte) bool {
	return len(data) >= 20 && le.Uint16(data) == 0 && le.Uint16(data[2:]) == 0xffff && le.Uint16(data[4:]) < 2
}

func parseCOFFImport(data []byte) (*coffImport, error) {
	size := le.Uint32(data[12:])
	if uint64(size) > uint64(len(data)-20) {
		return nil, errors.New("truncated COFF import member")
	}
	fields := bytes.SplitN(data[20:20+size], []byte{0}, 3)
	if len(fields) != 3 || len(fields[0]) == 0 {
		return nil, errors.New("malformed COFF import member")
	}
	// The low two bits of the type field are code, data or const.
	return &coffImport{name: string(fields[0]), dll: string(fields[1]), data: le.Uint16(data[18:])&3 == 1}, nil
}

func (f *coffImport) symbols() []string {
	if f.data {
		return []string{"__imp_" + f.name}
	}
	return []string{"__imp_" + f.name, f.name}
}

// defined is empty: a DLL import is not a definition that -prefix-symbols
// may rename or that binding edits may hide, since its name is also the
// name the DLL exports.
func (f *coffImport) defined() []string   { return nil }
func (f *coffImport) undefined() []string { return nil }

// indexNames lists both symbols, as import libraries index them.
func (f *coffImport) indexNames() []string { return f.symbols() }

// editCOFFImport leaves an import member as it is. Wraps and prefixes apply
// to references, which other members hold, and -keep-global-symbol and the
// other flags that act on every definition leave imports alone, as do section
// edits and -add-symbol, since it has no sections or symbol table. An edit that
// names one of its symbols would change which DLL export the name binds to,
// which bao does not do, so it is an error.
func editCOFFImport(data []byte, e Edits) (objectResult, error) {
	f, err := parseCOFFImport(data)
	if err != nil {
		return objectResult{}, err
	}
	if err := refuseImportEdits(f.symbols(), "this import member declares as an export of "+f.dll, e); err != nil {
		return objectResult{}, err
	}
	return objectResult{data: data}, nil
}

// refuseImportEdits rejects an edit that names one of an import library
// member's symbols.
func refuseImportEdits(names []string, what string, e Edits) error {
	v := e.Visibility
	for _, name := range names {
		var flag string
		_, renamed := e.Rename[name]
		switch {
		case renamed:
			flag = "-redefine-sym"
		case v.Localize.Match(name):
			flag = "-localize-symbol"
		case v.Globalize.Match(name):
			flag = "-globalize-symbol"
		case v.Weaken.Match(name):
			flag = "-weaken-symbol"
		case v.Strip.Match(name):
			flag = "-strip-symbol"
		}
		if flag != "" {
			return fmt.Errorf("%s names %s, which %s; DLL imports are not edited", flag, name, what)
		}
	}
	return nil
}
