package pecoff

import (
	"fmt"
	"strings"
)

func coffDirective(word string) (string, string) {
	word = strings.Trim(word, "\x00\" ")
	word = strings.TrimLeft(word, "-/")
	k, v, _ := strings.Cut(word, ":")
	return strings.ToLower(k), strings.Trim(v, "\"")
}

// Only the dynamic CRT profile is resolved through installed runtime DLLs.
// Static CRT default-library requests must never be silently discarded.
func validateDirectives(o *object, defs map[string]int, mismatches map[string]string) error {
	for _, s := range o.sections {
		if s.name != ".drectve" {
			continue
		}
		for _, word := range strings.Fields(strings.Trim(string(s.data), "\x00")) {
			key, value := coffDirective(word)
			switch key {
			case "include":
				if _, ok := defs[value]; !ok {
					return fmt.Errorf("undefined COFF /INCLUDE %s", value)
				}
			case "exclude-symbols":
				if _, ok := defs[value]; !ok {
					return fmt.Errorf("undefined COFF exclusion %s", value)
				}
			case "alternatename":
				a, b, ok := strings.Cut(value, "=")
				if !ok || a == "" || b == "" {
					return fmt.Errorf("invalid COFF alternate name %q", value)
				}
			case "defaultlib":
				switch strings.TrimSuffix(strings.ToLower(value), ".lib") {
				case "msvcrt", "oldnames", "vcruntime", "ucrt", "msvcprt":
				default:
					return fmt.Errorf("unsupported COFF default library %q: the Windows lifecycle profile requires the dynamic release CRT (/MD)", value)
				}
			case "failifmismatch":
				k, v, ok := strings.Cut(value, "=")
				if !ok {
					return fmt.Errorf("invalid COFF mismatch directive")
				}
				if prior, ok := mismatches[k]; ok && prior != v {
					return fmt.Errorf("COFF /FAILIFMISMATCH %s: %s versus %s", k, prior, v)
				}
				mismatches[k] = v
				if k == "RuntimeLibrary" && v != "MD_DynamicRelease" {
					return fmt.Errorf("unsupported Windows CRT profile %s", v)
				}
			default:
				return fmt.Errorf("unsupported COFF linker directive %q", word)
			}
		}
	}
	return nil
}

func (o *object) resolveAlternates(defs map[string]int, selected map[int]bool) error {
	aliases := map[string]string{}
	for _, s := range o.sections {
		if s.name == ".drectve" {
			for _, word := range strings.Fields(string(s.data)) {
				k, v := coffDirective(word)
				if k == "alternatename" {
					a, b, ok := strings.Cut(v, "=")
					if !ok {
						return fmt.Errorf("invalid COFF alternate name")
					}
					if prior, ok := aliases[a]; ok && prior != b {
						return fmt.Errorf("conflicting COFF alternate names")
					}
					aliases[a] = b
				}
			}
		}
	}
	for i := 0; i < len(o.symbols); {
		s := o.symbols[i]
		if s.StorageClass == 2 && s.SectionNumber == 0 {
			name := o.names[i]
			seen := map[string]bool{}
			for {
				if _, ok := defs[name]; ok {
					break
				}
				next, ok := aliases[name]
				if !ok {
					break
				}
				if seen[name] {
					return fmt.Errorf("cyclic COFF alternate names")
				}
				seen[name] = true
				name = next
			}
			o.names[i] = name
		}
		i += 1 + int(s.NumberOfAuxSymbols)
	}
	return nil
}
