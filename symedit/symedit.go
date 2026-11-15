// Package symedit renames symbols in native relocatable objects and archives
// before they are linked, as llvm-objcopy --redefine-sym and lld --wrap do,
// and changes their binding or removes them, as llvm-objcopy --localize-symbol,
// --keep-global-symbol and --strip-unneeded do.
// Every other byte of an object is preserved and an edited archive gets a new
// symbol index, so the results remain ordinary inputs to a native linker.
//
// Little-endian ELF64 and 64-bit Mach-O relocatable objects are supported.
// Names are C names: on Mach-O, edits add and match the leading underscore.
package symedit

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// Edits describes symbol changes. Every mapping applies to input names; the
// result of one edit is never edited again.
type Edits struct {
	// Rename maps an input name to a new name. It applies to every symbol with
	// that name, local or global and defined or undefined, except section and
	// file symbols.
	Rename map[string]string
	// Wrap lists global symbols to redirect with ld.lld --wrap semantics.
	// References to NAME go to __wrap_NAME, including those in an object that
	// defines NAME, and undefined __real_NAME becomes NAME.
	Wrap []string
	Visibility
}

// Visibility changes symbol bindings and removes symbols. Matching uses input
// names. Bindings change in llvm-objcopy's order: localize, keep-global,
// globalize, then weaken; removal follows.
type Visibility struct {
	// Localize makes matching defined symbols local. Common symbols stay global.
	Localize Matcher
	// LocalizeHidden makes defined hidden and internal symbols local.
	LocalizeHidden bool
	// KeepGlobal, when not empty, makes every other defined symbol local.
	KeepGlobal Matcher
	// Globalize makes matching defined symbols global.
	Globalize Matcher
	// Weaken makes matching global symbols, defined or undefined, weak.
	Weaken Matcher
	// Strip removes matching symbols. A symbol that a relocation or section
	// group names is an error.
	Strip Matcher
	// StripUnneeded removes local and undefined symbols that no relocation or
	// section group names, except section and ARM/RISC-V mapping symbols.
	StripUnneeded bool
}

func (v Visibility) empty() bool {
	return v.Localize.empty() && !v.LocalizeHidden && v.KeepGlobal.empty() && v.Globalize.empty() && v.Weaken.empty() && v.Strip.empty() && !v.StripUnneeded
}

// Matcher matches symbol names exactly or, from NewMatcher with wildcard, by
// shell patterns as llvm-objcopy --wildcard does. A name matches when it
// matches a pattern and no pattern prefixed with !.
type Matcher struct {
	names             map[string]bool
	patterns, negated []string
}

// NewMatcher matches names, which are path.Match patterns when wildcard is set.
func NewMatcher(names []string, wildcard bool) (Matcher, error) {
	m := Matcher{names: map[string]bool{}}
	for _, name := range names {
		if name == "" || strings.IndexByte(name, 0) >= 0 {
			return m, fmt.Errorf("invalid symbol name %q", name)
		}
		if !wildcard {
			m.names[name] = true
			continue
		}
		pattern, negated := strings.CutPrefix(name, "!")
		if _, err := path.Match(pattern, ""); err != nil {
			return m, fmt.Errorf("invalid symbol pattern %q", name)
		}
		if negated {
			m.negated = append(m.negated, pattern)
		} else {
			m.patterns = append(m.patterns, pattern)
		}
	}
	return m, nil
}

// Match reports whether name matches.
func (m Matcher) Match(name string) bool {
	matched := m.names[name]
	for _, p := range m.patterns {
		if matched {
			break
		}
		matched, _ = path.Match(p, name)
	}
	if !matched {
		return false
	}
	for _, p := range m.negated {
		if ok, _ := path.Match(p, name); ok {
			return false
		}
	}
	return true
}

func (m Matcher) empty() bool { return len(m.names) == 0 && len(m.patterns) == 0 }

// Validate rejects empty names and edits that would apply to the same input name.
func (e Edits) Validate() error {
	check := func(name string) error {
		if name == "" || strings.IndexByte(name, 0) >= 0 {
			return fmt.Errorf("invalid symbol name %q", name)
		}
		return nil
	}
	wrapped := map[string]bool{}
	for _, name := range e.Wrap {
		if err := check(name); err != nil {
			return err
		}
		wrapped[name] = true
	}
	for from, to := range e.Rename {
		if err := check(from); err != nil {
			return err
		}
		if err := check(to); err != nil {
			return err
		}
		if wrapped[from] {
			return fmt.Errorf("symbol %s is both wrapped and renamed", from)
		}
		if real, ok := strings.CutPrefix(from, "__real_"); ok && wrapped[real] {
			return fmt.Errorf("symbol %s is renamed but is the real name of wrapped %s", from, real)
		}
	}
	return nil
}

func (e Edits) empty() bool { return len(e.Rename) == 0 && len(e.Wrap) == 0 && e.Visibility.empty() }

// ParseNames reads llvm-objcopy symbol list files, such as for
// --keep-global-symbols: one name per line. Blank lines and text after # are
// ignored.
func ParseNames(r io.Reader) ([]string, error) {
	var out []string
	s := bufio.NewScanner(r)
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		text, _, _ := strings.Cut(s.Text(), "#")
		if name := strings.TrimSpace(text); name != "" {
			out = append(out, name)
		}
	}
	return out, s.Err()
}

// ParseRenames reads llvm-objcopy --redefine-syms lines: "OLD NEW" pairs
// separated by whitespace. Blank lines and text after # are ignored.
func ParseRenames(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	s := bufio.NewScanner(r)
	s.Buffer(nil, 1<<20)
	for line := 1; s.Scan(); line++ {
		text, _, _ := strings.Cut(s.Text(), "#")
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected OLD NEW", line)
		}
		if previous, ok := out[fields[0]]; ok && previous != fields[1] {
			return nil, fmt.Errorf("line %d: %s is already renamed to %s", line, fields[0], previous)
		}
		out[fields[0]] = fields[1]
	}
	return out, s.Err()
}

// Defined returns the sorted global and weak symbols that an object, or any
// member of an archive, defines. Common symbols count as definitions.
func Defined(data []byte) ([]string, error) {
	seen := map[string]bool{}
	add := func(object []byte) error {
		f, err := parseObject(object)
		if err != nil {
			return err
		}
		for _, name := range f.defined() {
			seen[name] = true
		}
		return nil
	}
	if isArchive(data) {
		members, err := regularMembers(data)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if err := add(m.Data); err != nil {
				return nil, fmt.Errorf("archive member %s: %w", m.Name, err)
			}
		}
	} else if err := add(data); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// Prefix renames each defined name to prefix+name. Undefined references to
// other names, such as C library imports, are left alone.
func Prefix(defined []string, prefix string) map[string]string {
	out := make(map[string]string, len(defined))
	for _, name := range defined {
		out[name] = prefix + name
	}
	return out
}

// Edit applies edits to an ELF relocatable object or to every member of an
// archive. It returns the input unchanged when there is nothing to edit, and
// otherwise a copy with the number of edits: renamed, rebound and removed
// symbol table entries plus redirected relocations.
//
// Each archive member is edited separately. A member that refers to a symbol
// another member no longer exports is an error, since the archive would no
// longer link; partially link such an archive into one object first.
func Edit(data []byte, e Edits) ([]byte, int, error) {
	if err := e.Validate(); err != nil {
		return nil, 0, err
	}
	if !isArchive(data) {
		r, err := editObject(data, e)
		return r.data, r.edited, err
	}
	return editArchive(data, e)
}

func isArchive(data []byte) bool {
	return bytes.HasPrefix(data, []byte("!<arch>\n")) || bytes.HasPrefix(data, []byte("!<thin>\n"))
}
