package toolchain

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
)

// IsLanguageRuntimeLibrary recognizes the standard shared C++/Rust/unwinder
// library names used by Bao's supported profiles. It audits declared imports;
// it does not inspect arbitrary native dlopen/LoadLibrary behavior.
func IsLanguageRuntimeLibrary(name string) bool {
	name = strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	return strings.Contains(name, "libstdc++") || strings.Contains(name, "libgcc_s") || strings.Contains(name, "libc++") || strings.Contains(name, "libunwind") || strings.Contains(name, "winpthread") || strings.HasPrefix(name, "vcruntime") || strings.HasPrefix(name, "msvcp") || strings.HasPrefix(name, "libstd-") || strings.HasPrefix(name, "std-")
}

func combineCOFFArchives(target Target, input, output string, dependencies []string) error {
	if len(dependencies) == 0 {
		// Preserve the existing single-input identity, including its archive
		// metadata and namespacing hash. Translation validates the COFF input.
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		return os.WriteFile(output, data, 0644)
	}
	var result bytes.Buffer
	result.WriteString("!<arch>\n")
	index := 0
	expected := uint16(0x8664)
	if target.Name == "windows/arm64" {
		expected = 0xaa64
	}
	for fileIndex, path := range append([]string{input}, dependencies...) {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		isArchive := bytes.HasPrefix(data, []byte("!<arch>\n"))
		if fileIndex > 0 && !isArchive {
			return fmt.Errorf("dependency %s must be a static archive for %s", path, target.Name)
		}
		members := []ar.Member{{Name: "input.obj", Data: data}}
		if isArchive {
			members, err = ar.ParseCOFFForMachine(data, expected)
			if err != nil {
				return err
			}
		}
		if len(members) == 0 {
			return fmt.Errorf("COFF input %s has no matching native members", path)
		}
		for _, m := range members {
			t, err := detectObject(m.Data)
			if err != nil {
				return fmt.Errorf("COFF input %s member %s: %w", path, m.Name, err)
			}
			if t.Name != target.Name {
				return fmt.Errorf("COFF input %s targets %s, expected %s", path, t.Name, target.Name)
			}
			// Stable synthetic metadata avoids platform filename encodings and
			// keeps the merged archive independent of producer filesystem paths.
			name := fmt.Sprintf("m%08d.obj/", index)
			index++
			fmt.Fprintf(&result, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0644, len(m.Data))
			result.Write(m.Data)
			if len(m.Data)%2 != 0 {
				result.WriteByte('\n')
			}
		}
	}
	return os.WriteFile(output, result.Bytes(), 0644)
}
