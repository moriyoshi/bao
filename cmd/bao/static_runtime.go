package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/toolchain"
)

func verifyStaticRuntimeImports(directory string) error {
	reject := func(name string) error {
		if toolchain.IsLanguageRuntimeLibrary(name) {
			return fmt.Errorf("static language runtime required, but generated native imports still need %s", name)
		}
		return nil
	}
	data, err := os.ReadFile(filepath.Join(directory, "bao-manifest.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		Imports     []map[string]any
		DataImports []map[string]any `json:"data_imports"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	for _, imp := range append(manifest.Imports, manifest.DataImports...) {
		for key, value := range imp {
			if strings.EqualFold(key, "Library") || strings.EqualFold(key, "DLL") {
				if name, ok := value.(string); ok {
					if err := reject(name); err != nil {
						return err
					}
				}
			}
		}
	}
	// Include dependencies introduced by the generated bootstrap/registration
	// code, such as an otherwise implicit libgcc_s unwind-registration import.
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			fields := strings.Fields(strings.TrimSpace(string(line)))
			if len(fields) >= 4 && fields[0] == "//go:cgo_import_dynamic" {
				name, err := strconv.Unquote(fields[len(fields)-1])
				if err != nil {
					return fmt.Errorf("invalid generated dynamic-library directive in %s", path)
				}
				if err := reject(name); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
