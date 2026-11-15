package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moriyoshi/bao/symedit"
)

// symbolEditFlags are the symbol edits shared by build and objcopy. In build,
// the binding and strip flags name their component first (PATH=SYMBOL,
// PATH=FILE or PATH); in objcopy they apply to the one input.
type symbolEditFlags struct {
	wrap, redefine, redefineFiles, prefixes symbolFlags
	scoped                                  bool
	localize, localizeFiles                 symbolFlags
	keepGlobal, keepGlobalFiles             symbolFlags
	globalize, weaken, strip                symbolFlags
	localizeHidden, stripUnneeded           symbolFlags // build: component paths
	localizeHiddenAll, stripUnneededAll     bool        // objcopy
	removeSection, onlySection, addSymbol   symbolFlags
	wildcard                                bool
}

func (f *symbolEditFlags) register(fs *flag.FlagSet, scoped bool, prefixUsage string) {
	f.scoped = scoped
	fs.Var(&f.wrap, "wrap", "redirect references to SYMBOL to __wrap_SYMBOL and __real_SYMBOL to SYMBOL, as ld.lld --wrap; repeatable")
	fs.Var(&f.redefine, "redefine-sym", "rename symbol OLD=NEW, defined or undefined; repeatable")
	fs.Var(&f.redefineFiles, "redefine-syms", "file of \"OLD NEW\" lines, as llvm-objcopy --redefine-syms; repeatable")
	fs.Var(&f.prefixes, "prefix-symbols", prefixUsage)
	symbol, file, where := "SYMBOL", "FILE", ""
	if scoped {
		symbol, file, where = "PATH=SYMBOL", "PATH=FILE", " in the input or -link-archive at PATH"
	}
	fs.Var(&f.localize, "localize-symbol", symbol+": make that definition"+where+" local; repeatable")
	fs.Var(&f.localizeFiles, "localize-symbols", file+": -localize-symbol for each line of FILE; repeatable")
	fs.Var(&f.keepGlobal, "keep-global-symbol", symbol+": keep that symbol global and make every other definition"+where+" local; repeatable")
	fs.Var(&f.keepGlobalFiles, "keep-global-symbols", file+": -keep-global-symbol for each line of FILE; repeatable")
	fs.Var(&f.globalize, "globalize-symbol", symbol+": make that definition"+where+" global; repeatable")
	fs.Var(&f.weaken, "weaken-symbol", symbol+": make that global symbol"+where+" weak; repeatable")
	fs.Var(&f.strip, "strip-symbol", symbol+": remove that symbol"+where+"; a symbol a relocation names is an error; repeatable")
	section, add := "SECTION", "NAME=[SECTION:]VALUE[,FLAGS]"
	if scoped {
		section, add = "PATH=SECTION", "PATH="+add
	}
	fs.Var(&f.removeSection, "remove-section", section+": remove that section"+where+", its relocations and its symbols; Mach-O sections are SEGMENT,SECTION; repeatable")
	fs.Var(&f.onlySection, "only-section", section+": keep only the matching sections"+where+", with their relocations; repeatable")
	fs.Var(&f.addSymbol, "add-symbol", add+": add a symbol"+where+" at an offset in SECTION, or an absolute one, as llvm-objcopy --add-symbol; FLAGS are global, local, weak, default, hidden, protected, object, function or notype; repeatable")
	if scoped {
		fs.Var(&f.localizeHidden, "localize-hidden", "PATH: make the hidden and internal definitions in the input or -link-archive at PATH local; repeatable")
		fs.Var(&f.stripUnneeded, "strip-unneeded", "PATH: remove the local and undefined symbols in the input or -link-archive at PATH that no relocation needs; repeatable")
	} else {
		fs.BoolVar(&f.localizeHiddenAll, "localize-hidden", false, "make hidden and internal definitions local")
		fs.BoolVar(&f.stripUnneededAll, "strip-unneeded", false, "remove local and undefined symbols that no relocation needs")
	}
	fs.BoolVar(&f.wildcard, "wildcard", false, "treat the names given to the localize, keep-global, globalize, weaken, strip and section flags as shell patterns; a pattern starting with ! excludes names")
}

func (f *symbolEditFlags) any() bool {
	return len(f.wrap) > 0 || len(f.redefine) > 0 || len(f.redefineFiles) > 0 || len(f.prefixes) > 0 || f.visibility()
}

func (f *symbolEditFlags) visibility() bool {
	return len(f.localize)+len(f.localizeFiles)+len(f.keepGlobal)+len(f.keepGlobalFiles)+len(f.globalize)+len(f.weaken)+len(f.strip)+len(f.localizeHidden)+len(f.stripUnneeded)+len(f.removeSection)+len(f.onlySection)+len(f.addSymbol) > 0 || f.localizeHiddenAll || f.stripUnneededAll
}

// edits returns the -wrap and -redefine-sym(s) edits, which apply to every input.
func (f *symbolEditFlags) edits() (symedit.Edits, error) {
	e := symedit.Edits{Rename: map[string]string{}, Wrap: append([]string{}, f.wrap...)}
	add := func(from, to, source string) error {
		if previous, ok := e.Rename[from]; ok && previous != to {
			return usage("%s renames %s to %s, but it is already renamed to %s", source, from, to, previous)
		}
		e.Rename[from] = to
		return nil
	}
	for _, path := range f.redefineFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return e, err
		}
		renames, err := symedit.ParseRenames(bytes.NewReader(data))
		if err != nil {
			return e, usage("-redefine-syms %s: %v", path, err)
		}
		for from, to := range renames {
			if err := add(from, to, "-redefine-syms "+path); err != nil {
				return e, err
			}
		}
	}
	for _, pair := range f.redefine {
		from, to, ok := strings.Cut(pair, "=")
		if !ok || from == "" || to == "" {
			return e, usage("-redefine-sym %q: expected OLD=NEW", pair)
		}
		if err := add(from, to, "-redefine-sym"); err != nil {
			return e, err
		}
	}
	if err := e.Validate(); err != nil {
		return e, usage("%v", err)
	}
	return e, nil
}

// visibilitySpec is the binding, strip and section edits of one component,
// also its build provenance.
type visibilitySpec struct {
	Path           string   `json:"path,omitempty"`
	Localize       []string `json:"localize,omitempty"`
	LocalizeHidden bool     `json:"localize_hidden,omitempty"`
	KeepGlobal     []string `json:"keep_global,omitempty"`
	Globalize      []string `json:"globalize,omitempty"`
	Weaken         []string `json:"weaken,omitempty"`
	Strip          []string `json:"strip,omitempty"`
	StripUnneeded  bool     `json:"strip_unneeded,omitempty"`
	RemoveSection  []string `json:"remove_section,omitempty"`
	OnlySection    []string `json:"only_section,omitempty"`
	AddSymbol      []string `json:"add_symbol,omitempty"`
}

// compile returns the component's edits, without the renames and wraps.
func (s *visibilitySpec) compile(wildcard bool) (symedit.Edits, error) {
	e := symedit.Edits{Visibility: symedit.Visibility{LocalizeHidden: s.LocalizeHidden, StripUnneeded: s.StripUnneeded}}
	var err error
	for _, m := range []struct {
		into  *symedit.Matcher
		names []string
	}{{&e.Localize, s.Localize}, {&e.KeepGlobal, s.KeepGlobal}, {&e.Globalize, s.Globalize}, {&e.Weaken, s.Weaken}, {&e.Strip, s.Strip}, {&e.RemoveSection, s.RemoveSection}, {&e.OnlySection, s.OnlySection}} {
		if *m.into, err = symedit.NewMatcher(m.names, wildcard); err != nil {
			return e, usage("%v", err)
		}
	}
	for _, spec := range s.AddSymbol {
		a, err := symedit.ParseAddSymbol(spec)
		if err != nil {
			return e, usage("%v", err)
		}
		e.AddSymbols = append(e.AddSymbols, a)
	}
	return e, nil
}

// visibilitySpecs groups the binding and strip flags by component path; the
// path is empty when unscoped.
func (f *symbolEditFlags) visibilitySpecs() ([]*visibilitySpec, error) {
	var specs []*visibilitySpec
	byPath := map[string]*visibilitySpec{}
	spec := func(path string) *visibilitySpec {
		s, ok := byPath[path]
		if !ok {
			s = &visibilitySpec{Path: path}
			byPath[path] = s
			specs = append(specs, s)
		}
		return s
	}
	split := func(name, value string) (string, string, error) {
		if !f.scoped {
			return "", value, nil
		}
		i := strings.LastIndexByte(value, '=')
		// An added symbol's own NAME=VALUE has one more =.
		if name == "add-symbol" && i > 0 {
			i = strings.LastIndexByte(value[:i], '=')
		}
		if i <= 0 || i == len(value)-1 {
			return "", "", usage("-%s %q: expected PATH=VALUE", name, value)
		}
		return value[:i], value[i+1:], nil
	}
	for _, flag := range []struct {
		name   string
		values symbolFlags
		file   bool
		into   func(*visibilitySpec) *[]string
	}{
		{"localize-symbol", f.localize, false, func(s *visibilitySpec) *[]string { return &s.Localize }},
		{"localize-symbols", f.localizeFiles, true, func(s *visibilitySpec) *[]string { return &s.Localize }},
		{"keep-global-symbol", f.keepGlobal, false, func(s *visibilitySpec) *[]string { return &s.KeepGlobal }},
		{"keep-global-symbols", f.keepGlobalFiles, true, func(s *visibilitySpec) *[]string { return &s.KeepGlobal }},
		{"globalize-symbol", f.globalize, false, func(s *visibilitySpec) *[]string { return &s.Globalize }},
		{"weaken-symbol", f.weaken, false, func(s *visibilitySpec) *[]string { return &s.Weaken }},
		{"strip-symbol", f.strip, false, func(s *visibilitySpec) *[]string { return &s.Strip }},
		{"remove-section", f.removeSection, false, func(s *visibilitySpec) *[]string { return &s.RemoveSection }},
		{"only-section", f.onlySection, false, func(s *visibilitySpec) *[]string { return &s.OnlySection }},
		{"add-symbol", f.addSymbol, false, func(s *visibilitySpec) *[]string { return &s.AddSymbol }},
	} {
		for _, value := range flag.values {
			path, arg, err := split(flag.name, value)
			if err != nil {
				return nil, err
			}
			names := []string{arg}
			if flag.file {
				data, err := os.ReadFile(arg)
				if err != nil {
					return nil, err
				}
				if names, err = symedit.ParseNames(bytes.NewReader(data)); err != nil {
					return nil, usage("-%s %s: %v", flag.name, arg, err)
				}
			}
			into := flag.into(spec(path))
			*into = append(*into, names...)
		}
	}
	for _, path := range f.localizeHidden {
		spec(path).LocalizeHidden = true
	}
	for _, path := range f.stripUnneeded {
		spec(path).StripUnneeded = true
	}
	if f.localizeHiddenAll {
		spec("").LocalizeHidden = true
	}
	if f.stripUnneededAll {
		spec("").StripUnneeded = true
	}
	for _, s := range specs {
		if _, err := s.compile(f.wildcard); err != nil {
			return nil, err
		}
	}
	return specs, nil
}

// editComponent is one relocatable input of a build: the primary input or a
// -link-archive, as named on the command line.
type editComponent struct {
	path string
	data []byte
}

// symbolEditRecord is the build provenance of the edits.
type symbolEditRecord struct {
	Wrap       []string          `json:"wrap,omitempty"`
	Rename     map[string]string `json:"rename,omitempty"`
	Prefixes   []prefixRecord    `json:"prefixes,omitempty"`
	Visibility []*visibilitySpec `json:"visibility,omitempty"`
	Wildcard   bool              `json:"wildcard,omitempty"`
	// CombinedFirst records that the primary archive was partially linked on
	// its own before its bindings changed.
	CombinedFirst bool `json:"combined_first,omitempty"`
	Edited        int  `json:"edited"`
}

type prefixRecord struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
}

// buildEdits are the resolved edits of a build's components.
type buildEdits struct {
	base       symedit.Edits
	prefixOf   []string
	visibility []symedit.Edits
	rebinds    []bool
	record     *symbolEditRecord
}

// resolveBuild matches every component-scoped flag to a component by file
// identity. It reads no component data, so a component can still be replaced,
// such as by partially linking the primary archive.
func (f *symbolEditFlags) resolveBuild(components []editComponent) (*buildEdits, error) {
	if !f.any() {
		return nil, nil
	}
	base, err := f.edits()
	if err != nil {
		return nil, err
	}
	b := &buildEdits{base: base, prefixOf: make([]string, len(components)), visibility: make([]symedit.Edits, len(components)), rebinds: make([]bool, len(components))}
	b.record = &symbolEditRecord{Wrap: base.Wrap, Rename: base.Rename, Wildcard: f.wildcard}
	stats := make([]os.FileInfo, len(components))
	for i, c := range components {
		if stats[i], err = os.Stat(c.path); err != nil {
			return nil, err
		}
	}
	match := func(flag, path string) ([]int, error) {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, usage("-%s %s: %v", flag, path, err)
		}
		var out []int
		for j := range components {
			if os.SameFile(stat, stats[j]) {
				out = append(out, j)
			}
		}
		if len(out) == 0 {
			return nil, usage("-%s %s names neither the input nor a -link-archive", flag, path)
		}
		return out, nil
	}
	for _, spec := range f.prefixes {
		i := strings.LastIndexByte(spec, '=')
		if i <= 0 || i == len(spec)-1 {
			return nil, usage("-prefix-symbols %q: expected PATH=PREFIX", spec)
		}
		path, prefix := spec[:i], spec[i+1:]
		matched, err := match("prefix-symbols", path)
		if err != nil {
			return nil, err
		}
		for _, j := range matched {
			if b.prefixOf[j] != "" && b.prefixOf[j] != prefix {
				return nil, usage("-prefix-symbols gives %s both %s and %s", path, b.prefixOf[j], prefix)
			}
			if b.prefixOf[j] == "" {
				b.prefixOf[j] = prefix
				b.record.Prefixes = append(b.record.Prefixes, prefixRecord{path, prefix})
			}
		}
	}
	specs, err := f.visibilitySpecs()
	if err != nil {
		return nil, err
	}
	owner := make([]string, len(components))
	for _, s := range specs {
		matched, err := match("localize/keep-global/globalize/weaken/strip/section", s.Path)
		if err != nil {
			return nil, err
		}
		v, _ := s.compile(f.wildcard)
		for _, j := range matched {
			if owner[j] != "" {
				return nil, usage("%s and %s name the same input; give its binding and strip flags one path", owner[j], s.Path)
			}
			owner[j] = s.Path
			b.visibility[j], b.rebinds[j] = v, true
		}
		b.record.Visibility = append(b.record.Visibility, s)
	}
	return b, nil
}

// changesBindings reports whether component i has binding, strip or section
// edits.
func (b *buildEdits) changesBindings(i int) bool {
	return b != nil && b.rebinds[i]
}

// apply edits the components in place. -wrap and -redefine-sym(s) apply to
// every component. -prefix-symbols PATH=PREFIX renames the definitions of the
// components sharing PREFIX, and only their references to them; every other
// reference, such as a C library import, keeps its name. A wrapped or
// explicitly renamed symbol is not also prefixed. The binding and strip flags
// apply to their own component.
func (b *buildEdits) apply(components []editComponent, stderr io.Writer) (*symbolEditRecord, error) {
	if b == nil {
		return nil, nil
	}
	renames := map[string]map[string]string{}
	for j, prefix := range b.prefixOf {
		if prefix == "" {
			continue
		}
		names, err := symedit.Defined(components[j].data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", components[j].path, err)
		}
		if renames[prefix] == nil {
			renames[prefix] = map[string]string{}
		}
		for from, to := range symedit.Prefix(names, prefix) {
			renames[prefix][from] = to
		}
	}
	for i := range components {
		e := b.base
		if prefix := b.prefixOf[i]; prefix != "" {
			e.Rename = map[string]string{}
			for from, to := range renames[prefix] {
				if !wrappedName(b.base.Wrap, from) {
					e.Rename[from] = to
				}
			}
			for from, to := range b.base.Rename {
				e.Rename[from] = to
			}
		}
		c := b.visibility[i]
		e.Visibility, e.RemoveSection, e.OnlySection, e.AddSymbols = c.Visibility, c.RemoveSection, c.OnlySection, c.AddSymbols
		edited, n, err := symedit.Edit(components[i].data, e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", components[i].path, err)
		}
		components[i].data = edited
		b.record.Edited += n
	}
	fmt.Fprintf(stderr, "Edited %d symbols and references in %d inputs\n", b.record.Edited, len(components))
	return b.record, nil
}

func objcopy(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("objcopy", "objcopy [options] input output", "Rename, wrap, localize, strip or add symbols, or remove sections, in an ELF, Mach-O or COFF relocatable object or archive, as llvm-objcopy and ld.lld --wrap do. Mach-O names omit the C underscore. Other object bytes are preserved; an edited archive gets a new GNU, BSD or Microsoft symbol index. The output must not exist.")
	var f symbolEditFlags
	f.register(fs, false, "prefix every symbol the input defines, and the input's references to them, with PREFIX; other undefined references keep their names")
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usage("objcopy requires an input and a new output")
	}
	if len(f.prefixes) > 1 {
		return usage("-prefix-symbols may be given once")
	}
	e, err := f.edits()
	if err != nil {
		return err
	}
	specs, err := f.visibilitySpecs()
	if err != nil {
		return err
	}
	if len(specs) == 1 {
		c, _ := specs[0].compile(f.wildcard)
		e.Visibility, e.RemoveSection, e.OnlySection, e.AddSymbols = c.Visibility, c.RemoveSection, c.OnlySection, c.AddSymbols
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if len(f.prefixes) == 1 {
		if f.prefixes[0] == "" {
			return usage("-prefix-symbols requires a prefix")
		}
		defined, err := symedit.Defined(data)
		if err != nil {
			return err
		}
		rename := map[string]string{}
		for from, to := range symedit.Prefix(defined, f.prefixes[0]) {
			if !wrappedName(e.Wrap, from) {
				rename[from] = to
			}
		}
		for from, to := range e.Rename {
			rename[from] = to
		}
		e.Rename = rename
	}
	out, n, err := symedit.Edit(data, e)
	if err != nil {
		return err
	}
	if err := writeNew(fs.Arg(1), out); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Edited %d symbols and references\n", n)
	return nil
}

func wrappedName(wrap []string, name string) bool {
	for _, w := range wrap {
		if name == w || name == "__real_"+w {
			return true
		}
	}
	return false
}
