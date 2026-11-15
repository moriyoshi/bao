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

// symbolEditFlags are the symbol edits shared by build and objcopy.
type symbolEditFlags struct {
	wrap, redefine, redefineFiles, prefixes symbolFlags
}

func (f *symbolEditFlags) register(fs *flag.FlagSet, prefixUsage string) {
	fs.Var(&f.wrap, "wrap", "redirect references to SYMBOL to __wrap_SYMBOL and __real_SYMBOL to SYMBOL, as ld.lld --wrap; repeatable")
	fs.Var(&f.redefine, "redefine-sym", "rename symbol OLD=NEW, defined or undefined; repeatable")
	fs.Var(&f.redefineFiles, "redefine-syms", "file of \"OLD NEW\" lines, as llvm-objcopy --redefine-syms; repeatable")
	fs.Var(&f.prefixes, "prefix-symbols", prefixUsage)
}

func (f *symbolEditFlags) any() bool {
	return len(f.wrap) > 0 || len(f.redefine) > 0 || len(f.redefineFiles) > 0 || len(f.prefixes) > 0
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

// editComponent is one relocatable input of a build: the primary input or a
// -link-archive, as named on the command line.
type editComponent struct {
	path string
	data []byte
}

// symbolEditRecord is the build provenance of the edits.
type symbolEditRecord struct {
	Wrap     []string          `json:"wrap,omitempty"`
	Rename   map[string]string `json:"rename,omitempty"`
	Prefixes []prefixRecord    `json:"prefixes,omitempty"`
	Edited   int               `json:"edited"`
}

type prefixRecord struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
}

// applyBuild edits the components in place. -wrap and -redefine-sym(s) apply
// to every component. -prefix-symbols PATH=PREFIX renames the definitions of
// the components sharing PREFIX, and only their references to them; every
// other reference, such as a C library import, keeps its name. A wrapped or
// explicitly renamed symbol is not also prefixed.
func (f *symbolEditFlags) applyBuild(components []editComponent, stderr io.Writer) (*symbolEditRecord, error) {
	if !f.any() {
		return nil, nil
	}
	base, err := f.edits()
	if err != nil {
		return nil, err
	}
	record := &symbolEditRecord{Wrap: base.Wrap, Rename: base.Rename}
	groups := map[string][]int{}
	prefixOf := make([]string, len(components))
	stats := make([]os.FileInfo, len(components))
	for i, c := range components {
		if stats[i], err = os.Stat(c.path); err != nil {
			return nil, err
		}
	}
	for _, spec := range f.prefixes {
		i := strings.LastIndexByte(spec, '=')
		if i <= 0 || i == len(spec)-1 {
			return nil, usage("-prefix-symbols %q: expected PATH=PREFIX", spec)
		}
		path, prefix := spec[:i], spec[i+1:]
		stat, err := os.Stat(path)
		if err != nil {
			return nil, usage("-prefix-symbols %s: %v", path, err)
		}
		matched := false
		for j := range components {
			if !os.SameFile(stat, stats[j]) {
				continue
			}
			if prefixOf[j] != "" && prefixOf[j] != prefix {
				return nil, usage("-prefix-symbols gives %s both %s and %s", path, prefixOf[j], prefix)
			}
			if prefixOf[j] == "" {
				prefixOf[j] = prefix
				groups[prefix] = append(groups[prefix], j)
				record.Prefixes = append(record.Prefixes, prefixRecord{path, prefix})
			}
			matched = true
		}
		if !matched {
			return nil, usage("-prefix-symbols %s names neither the input nor a -link-archive", path)
		}
	}
	renames := map[string]map[string]string{}
	for prefix, members := range groups {
		var defined []string
		for _, j := range members {
			names, err := symedit.Defined(components[j].data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", components[j].path, err)
			}
			defined = append(defined, names...)
		}
		renames[prefix] = symedit.Prefix(defined, prefix)
	}
	for i := range components {
		e := base
		if prefix := prefixOf[i]; prefix != "" {
			e.Rename = map[string]string{}
			for from, to := range renames[prefix] {
				if !wrappedName(base.Wrap, from) {
					e.Rename[from] = to
				}
			}
			for from, to := range base.Rename {
				e.Rename[from] = to
			}
		}
		edited, n, err := symedit.Edit(components[i].data, e)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", components[i].path, err)
		}
		components[i].data = edited
		record.Edited += n
	}
	fmt.Fprintf(stderr, "Edited %d symbol references in %d inputs\n", record.Edited, len(components))
	return record, nil
}

func objcopy(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("objcopy", "objcopy [options] input output", "Rename symbols in an ELF relocatable object or archive, as llvm-objcopy and ld.lld --wrap do. Other object bytes are preserved; an edited archive gets a new GNU symbol index. The output must not exist.")
	var f symbolEditFlags
	f.register(fs, "prefix every symbol the input defines, and the input's references to them, with PREFIX; other undefined references keep their names")
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
	fmt.Fprintf(stderr, "Edited %d symbol references\n", n)
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
