// Package bindings produces fixed-signature Go/native ABI adapters.
package bindings

import (
	"encoding/json"
	"fmt"
	"go/token"
	"io"
	"strings"
)

type Manifest struct {
	Schema    int        `json:"schema"`
	ABI       string     `json:"abi"`
	Functions []Function `json:"functions"`
}
type Function struct {
	Name   string   `json:"name"`
	Symbol string   `json:"symbol"`
	Params []string `json:"params"`
	Result string   `json:"result,omitempty"`
}

func Parse(r io.Reader) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return m, fmt.Errorf("expected one signature manifest")
	}
	return m, m.Validate()
}
func (m Manifest) Validate() error {
	if m.Schema != 1 || m.ABI != "c" || len(m.Functions) == 0 {
		return fmt.Errorf("signature manifest requires schema 1, abi c, and functions")
	}
	names := map[string]bool{}
	for _, f := range m.Functions {
		if !token.IsExported(f.Name) || !token.IsIdentifier(f.Name) || !token.IsIdentifier(f.Symbol) || names[f.Name] || f.Name == "G" || f.Name == "ThreadStart" || f.Name == "FinalizeRuntime" || strings.HasPrefix(f.Name, "TLS") || strings.HasPrefix(f.Name, "SymbolAddr") {
			return fmt.Errorf("invalid, duplicate or reserved binding %q", f.Name)
		}
		names[f.Name] = true
		if len(f.Params) > 32 {
			return fmt.Errorf("%s exceeds 32 scalar arguments", f.Name)
		}
		for _, p := range f.Params {
			if !Scalar(p) {
				return fmt.Errorf("%s: unsupported parameter type %q", f.Name, p)
			}
		}
		if f.Result != "" && f.Result != "void" && !Scalar(f.Result) {
			return fmt.Errorf("%s: unsupported result type %q", f.Name, f.Result)
		}
	}
	return nil
}
func Scalar(s string) bool {
	switch s {
	case "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "uintptr", "pointer", "float32", "float64":
		return true
	}
	return false
}
func GoType(s string) string {
	if s == "pointer" {
		return "unsafe.Pointer"
	}
	if s == "void" {
		return ""
	}
	return s
}
