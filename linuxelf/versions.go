package linuxelf

import (
	"debug/elf"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// symbolVersion is a version name such as GLIBC_2.3.2: a namespace and its
// release numbers. A name without release numbers, such as GLIBC_PRIVATE,
// does not parse.
type symbolVersion struct {
	space   string
	release []int
}

func parseSymbolVersion(name string) (symbolVersion, bool) {
	i := strings.LastIndexByte(name, '_')
	if i <= 0 || i == len(name)-1 {
		return symbolVersion{}, false
	}
	v := symbolVersion{space: name[:i]}
	for _, part := range strings.Split(name[i+1:], ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return symbolVersion{}, false
		}
		v.release = append(v.release, n)
	}
	return v, true
}

// less orders two releases of one namespace.
func (v symbolVersion) less(w symbolVersion) bool {
	for i := 0; i < len(v.release) && i < len(w.release); i++ {
		if v.release[i] != w.release[i] {
			return v.release[i] < w.release[i]
		}
	}
	return len(v.release) < len(w.release)
}

// ParseMaxSymbolVersions validates -linux-max-symbol-version caps, at most one
// per namespace, such as GLIBC_2.17 and GLIBCXX_3.4.19.
func ParseMaxSymbolVersions(names []string) (map[string]symbolVersion, error) {
	caps := map[string]symbolVersion{}
	for _, name := range names {
		v, ok := parseSymbolVersion(name)
		if !ok {
			return nil, fmt.Errorf("invalid maximum symbol version %q: use a version name such as GLIBC_2.17", name)
		}
		if _, ok := caps[v.space]; ok {
			return nil, fmt.Errorf("more than one maximum symbol version for %s", v.space)
		}
		caps[v.space] = v
	}
	return caps, nil
}

// bindVersions sets the version each import of a relocatable input binds, as
// a static linker records one in verneed. ld.so binds an unversioned
// reference to a symbol's oldest version, which can be a compatibility ABI:
// x86_64 pthread_cond_init@GLIBC_2.2.5 rejects a CLOCK_MONOTONIC condattr.
//
// An import binds the default (@@) version its sysroot library defines. Under
// a cap for that version's namespace, it binds the newest version at or below
// the cap, which keeps the result loadable by the glibc the inputs were built
// for. When every version is newer, the import stays unversioned: a version
// requirement would stop the image loading on that glibc even if the import
// is never used, while an unversioned one fails only when bound. It returns
// those imports as NAME@OLDEST.
func bindVersions(root string, imports []Import, caps map[string]symbolVersion) ([]string, error) {
	type defined struct {
		name   string
		hidden bool
	}
	cache := map[string]map[string][]defined{}
	var above []string
	for i, b := range imports {
		versions, ok := cache[b.Library]
		if !ok {
			path := sysrootLibrary(root, b.Library)
			if path == "" {
				return nil, fmt.Errorf("missing target library %s", b.Library)
			}
			f, err := elf.Open(path)
			if err != nil {
				return nil, err
			}
			syms, err := f.DynamicSymbols()
			f.Close()
			if err != nil {
				return nil, err
			}
			versions = map[string][]defined{}
			for _, s := range syms {
				if s.Section != elf.SHN_UNDEF && s.HasVersion && s.Version != "" && s.Library == "" {
					versions[s.Name] = append(versions[s.Name], defined{s.Version, s.VersionIndex.IsHidden()})
				}
			}
			cache[b.Library] = versions
		}
		choice := ""
		for _, d := range versions[b.Remote] {
			if !d.hidden {
				choice = d.name
			}
		}
		if choice == "" {
			continue
		}
		v, ok := parseSymbolVersion(choice)
		if limit, capped := caps[v.space]; ok && capped && limit.less(v) {
			var best, oldest *symbolVersion
			var bestName, oldestName string
			for _, d := range versions[b.Remote] {
				w, ok := parseSymbolVersion(d.name)
				if !ok || w.space != v.space {
					continue
				}
				if !limit.less(w) && (best == nil || best.less(w)) {
					best, bestName = &w, d.name
				}
				if oldest == nil || w.less(*oldest) {
					oldest, oldestName = &w, d.name
				}
			}
			if best == nil {
				above = append(above, b.Remote+"@"+oldestName)
				continue
			}
			choice = bestName
		}
		imports[i].Version = choice
	}
	sort.Strings(above)
	return above, nil
}
