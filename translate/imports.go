package translate

import (
	"bufio"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ImportBinding struct {
	Original   string `json:"mach_o_symbol"`
	Local      string `json:"go_symbol"`
	Remote     string `json:"dynamic_symbol"`
	Library    string `json:"library"`
	CallSymbol string `json:"native_call_symbol,omitempty"`
}

type PointerFixup struct {
	Symbol      string `json:"location_symbol"`
	ImportLocal string `json:"import_symbol"`
	Addend      uint64 `json:"addend"`
}

// tbdSymbols reads only the v4 text-stub features needed for a system symbol
// index. It is not a general YAML parser. Unsupported inputs fail explicitly;
// source code, SDK binaries and complete stub files are never distributed.
func tbdSymbols(data []byte) (string, []string, error) {
	return tbdSymbolsForArch(data, "arm64")
}

func tbdSymbolsForArch(data []byte, arch string) (string, []string, error) {
	if !strings.HasPrefix(string(data), "--- !tapi-tbd") {
		return "", nil, fmt.Errorf("requires a v4 text-based dylib stub")
	}
	var library, section string
	var symbols []string
	allowed := false
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	lines.Buffer(make([]byte, 4096), 16<<20)
	readList := func(value string) ([]string, error) {
		for !strings.Contains(value, "]") && lines.Scan() {
			value += " " + strings.TrimSpace(lines.Text())
		}
		start, end := strings.IndexByte(value, '['), strings.IndexByte(value, ']')
		if start < 0 || end < start {
			return nil, fmt.Errorf("unsupported stub list")
		}
		var out []string
		for _, item := range strings.Split(value[start+1:end], ",") {
			item = strings.TrimSpace(item)
			if len(item) >= 2 && (item[0] == '\'' && item[len(item)-1] == '\'' || item[0] == '"' && item[len(item)-1] == '"') {
				item = item[1 : len(item)-1]
			}
			if item != "" {
				out = append(out, item)
			}
		}
		return out, nil
	}
	for lines.Scan() {
		raw := lines.Text()
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "---") {
			section = ""
			allowed = false
			continue
		}
		if strings.HasPrefix(line, "tbd-version:") && strings.TrimSpace(strings.TrimPrefix(line, "tbd-version:")) != "4" {
			return "", nil, fmt.Errorf("unsupported text-stub version")
		}
		if strings.HasPrefix(line, "install-name:") && library == "" {
			library = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "install-name:")), "\"'")
		}
		if len(raw) > 0 && raw[0] != ' ' && strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
		}
		if strings.HasPrefix(line, "targets:") || strings.HasPrefix(line, "- targets:") {
			list, err := readList(line)
			if err != nil {
				return "", nil, err
			}
			allowed = false
			for _, target := range list {
				if target == arch+"-macos" || arch == "arm64" && target == "arm64e-macos" || arch == "amd64" && target == "x86_64-macos" {
					allowed = true
				}
			}
		}
		if allowed && (section == "exports" || section == "reexports") && (strings.HasPrefix(line, "symbols:") || strings.HasPrefix(line, "weak-symbols:")) {
			list, err := readList(line)
			if err != nil {
				return "", nil, err
			}
			symbols = append(symbols, list...)
		}
	}
	if err := lines.Err(); err != nil {
		return "", nil, err
	}
	if library == "" || (!strings.HasPrefix(library, "/usr/lib/") && !strings.HasPrefix(library, "/System/Library/")) {
		return "", nil, fmt.Errorf("not an absolute system install name")
	}
	return library, symbols, nil
}

func SDKImports(sdk string) (map[string]string, error) {
	return SDKImportsForArch(sdk, "arm64")
}

func SDKImportsForArch(sdk, arch string) (map[string]string, error) {
	paths := []string{"usr/lib/libSystem.tbd", "usr/lib/libobjc.tbd", "usr/lib/libc++.tbd"}
	for _, name := range []string{"CoreFoundation", "Foundation", "AppKit", "Cocoa", "Metal", "QuartzCore", "CoreVideo", "CoreText", "CoreGraphics", "ColorSync", "Security", "SystemConfiguration", "IOKit", "CoreServices", "Carbon", "UserNotifications", "UniformTypeIdentifiers", "ImageIO", "Accelerate"} {
		paths = append(paths, "System/Library/Frameworks/"+name+".framework/"+name+".tbd")
	}
	index := make(map[string]string)
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(sdk, path))
		if err != nil {
			return nil, err
		}
		lib, names, err := tbdSymbolsForArch(data, arch)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, name := range names {
			if _, ok := index[name]; !ok {
				index[name] = lib
			}
		}
	}
	return index, nil
}

// BindSystemImports retains OS dynamic linkage in the final executable. Pointer
// constants need a native-data initialization fixup because Go rejects native
// absolute pointer relocations to dynamic symbols. Only writable __DATA fields
// are patched; no executable pages or Go pointers are involved.
func (p *TLSProbe) BindSystemImports(sdk string) error {
	arch := p.Arch
	if arch == "" {
		arch = "arm64"
	}
	index, err := SDKImportsForArch(sdk, arch)
	if err != nil {
		return err
	}
	return p.bindSystemImports(index)
}

// UnresolvedError lists every import the macOS SDK does not export.
type UnresolvedError struct{ Names []string }

func (e *UnresolvedError) Error() string {
	if len(e.Names) == 1 {
		return fmt.Sprintf("system SDK does not export %s for macOS/arm64", e.Names[0])
	}
	return fmt.Sprintf("system SDK does not export %d symbols for macOS/arm64: %s", len(e.Names), strings.Join(e.Names, ", "))
}

func (p *TLSProbe) bindSystemImports(index map[string]string) error {
	models := make([]*objectImage, len(p.Objects))
	defined := make(map[string]bool)
	undefined := make(map[string]bool)
	for i, o := range p.Objects {
		m, err := readImage(o)
		if err != nil {
			return err
		}
		models[i] = m
		for _, s := range m.symbols {
			if s.Type&0xe0 == 0 && s.Type&1 != 0 {
				if s.Sect != 0 {
					defined[s.Name] = true
				} else {
					undefined[s.Name] = true
				}
			}
		}
	}
	var names []string
	for name := range undefined {
		if !defined[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	bindings := make(map[string]ImportBinding)
	var unresolved []string
	for i, name := range names {
		lib, ok := index[name]
		if !ok {
			unresolved = append(unresolved, name)
			continue
		}
		binding := ImportBinding{Original: name, Local: fmt.Sprintf("%simport_%d", p.Namespace, i), Remote: strings.TrimPrefix(name, "_"), Library: lib}
		bindings[name] = binding
		p.Imports = append(p.Imports, binding)
	}
	if len(unresolved) != 0 {
		return &UnresolvedError{Names: unresolved}
	}
	for oi, m := range models {
		callSymbols := make(map[string]uint32)
		for si := range m.sections {
			s := &m.sections[si]
			var rels []macho.Reloc
			for _, r := range s.relocs {
				if r.Extern && r.Type != 10 {
					if int(r.Value) >= len(m.symbols) {
						return fmt.Errorf("invalid import symbol index")
					}
					binding, bound := bindings[m.symbols[r.Value].Name]
					if bound && r.Type == 2 {
						if !r.Pcrel || r.Len != 2 {
							return fmt.Errorf("unsupported native import branch form")
						}
						idx, ok := callSymbols[binding.Local]
						if !ok {
							idx = uint32(len(m.symbols))
							callSymbols[binding.Local] = idx
							m.symbols = append(m.symbols, macho.Symbol{Name: "_" + binding.Local + "_call", Type: 1})
						}
						r.Value = idx
						binding.CallSymbol = binding.Local + "_call"
						bindings[binding.Original] = binding
					}
					if bound && r.Type == 0 {
						if s.seg != "__DATA" || r.Len != 3 || r.Pcrel || uint64(r.Addr)+8 > uint64(len(s.data)) {
							return fmt.Errorf("unsupported dynamic pointer relocation in %s/%s", s.seg, s.name)
						}
						name := fmt.Sprintf("%sfixup_%d", p.Namespace, len(p.Fixups))
						p.Fixups = append(p.Fixups, PointerFixup{Symbol: name, ImportLocal: binding.Local, Addend: binary.LittleEndian.Uint64(s.data[r.Addr:])})
						m.symbols = append(m.symbols, macho.Symbol{Name: "_" + name, Type: 0xf, Sect: uint8(si + 1), Value: s.addr + uint64(r.Addr)})
						binary.LittleEndian.PutUint64(s.data[r.Addr:], 0)
						continue
					}
				}
				rels = append(rels, r)
			}
			s.relocs = rels
		}
		for i := range m.symbols {
			if b, ok := bindings[m.symbols[i].Name]; ok {
				m.symbols[i].Name = "_" + b.Local
			}
		}
		data, err := m.encode()
		if err != nil {
			return err
		}
		p.Objects[oi].Data = data
	}
	for i := range p.Imports {
		p.Imports[i] = bindings[p.Imports[i].Original]
	}
	return nil
}
