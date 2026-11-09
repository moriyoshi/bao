package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/verify"
)

// buildSettings is the -settings file. Every field mirrors a command-line flag.
// Paths are relative to the file and may use ${VAR}; an unset variable fails.
type buildSettings struct {
	Schema               int             `json:"schema"`
	Target               string          `json:"target"`
	Package              string          `json:"package"`
	Input                string          `json:"input"`
	Symbols              []string        `json:"symbols"`
	Bindings             json.RawMessage `json:"bindings"`
	StripDebug           *bool           `json:"strip_debug"`
	LinkArchives         []string        `json:"link_archives"`
	LinkNotices          []string        `json:"link_notices"`
	RequireStaticRuntime *bool           `json:"require_static_runtime"`
	Cargo                *struct {
		ManifestPath string `json:"manifest_path"`
		Package      string `json:"package"`
		Offline      *bool  `json:"offline"`
		Locked       *bool  `json:"locked"`
	} `json:"cargo"`
	Darwin *struct {
		platformLinkSettings
		SDK    string `json:"sdk"`
		MinOS  string `json:"min_os"`
		Linker string `json:"ld"`
	} `json:"darwin"`
	Linux *struct {
		platformLinkSettings
		Sysroot         string   `json:"sysroot"`
		Linker          string   `json:"ld"`
		SystemLibraries []string `json:"system_libraries"`
	} `json:"linux"`
	Windows *struct {
		platformLinkSettings
		Imports          map[string]string `json:"imports"`
		ImportLibraries  []string          `json:"import_libraries"`
		CXXRuntime       string            `json:"cxx_runtime"`
		CRT              string            `json:"crt"`
		MaxDataAlignment *uint             `json:"max_data_alignment"`
	} `json:"windows"`
}

// platformLinkSettings adds to the common link settings for one platform.
type platformLinkSettings struct {
	LinkArchives         []string `json:"link_archives"`
	LinkNotices          []string `json:"link_notices"`
	RequireStaticRuntime *bool    `json:"require_static_runtime"`
}

var settingsVariable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// applySettings fills flags the command line left unset and returns the
// positional arguments. A flag given on the command line replaces its setting,
// including every entry of a repeatable flag.
func (o *nativeFlags) applySettings(fs *flag.FlagSet) ([]string, error) {
	positional := fs.Args()
	if o.settings == "" {
		return positional, nil
	}
	data, err := os.ReadFile(o.settings)
	if err != nil {
		return nil, err
	}
	var s buildSettings
	if err := verify.Decode(data, &s); err != nil {
		return nil, usage("-settings %s: %v", o.settings, err)
	}
	if s.Schema != 1 {
		return nil, usage("-settings %s: unsupported schema %d; expected 1", o.settings, s.Schema)
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	dir, err := filepath.Abs(filepath.Dir(o.settings))
	if err != nil {
		return nil, err
	}
	path := func(value string) (string, error) {
		var missing string
		value = settingsVariable.ReplaceAllStringFunc(value, func(match string) string {
			name := settingsVariable.FindStringSubmatch(match)[1]
			expanded, ok := os.LookupEnv(name)
			if !ok {
				missing = name
			}
			return expanded
		})
		if missing != "" {
			return "", usage("-settings %s: environment variable %s is not set", o.settings, missing)
		}
		if value != "" && !filepath.IsAbs(value) {
			value = filepath.Join(dir, value)
		}
		return value, nil
	}
	set := func(name string, values ...string) error {
		if visited[name] || len(values) == 0 {
			return nil
		}
		if fs.Lookup(name) == nil {
			return usage("-settings %s: the -%s setting does not apply to bao %s", o.settings, name, fs.Name())
		}
		for _, value := range values {
			if err := fs.Set(name, value); err != nil {
				return usage("-settings %s: -%s: %v", o.settings, name, err)
			}
		}
		return nil
	}
	setText := func(name, value string) error {
		if value == "" {
			return nil
		}
		return set(name, value)
	}
	setBool := func(name string, value *bool) error {
		if value == nil {
			return nil
		}
		return set(name, strconv.FormatBool(*value))
	}
	setPaths := func(name string, values ...string) error {
		resolved := make([]string, 0, len(values))
		for _, value := range values {
			if value == "" {
				continue
			}
			p, err := path(value)
			if err != nil {
				return err
			}
			resolved = append(resolved, p)
		}
		return set(name, resolved...)
	}
	// A linker may be a bare command found on PATH.
	setLinker := func(value string) error {
		if strings.ContainsRune(value, filepath.Separator) || settingsVariable.MatchString(value) {
			return setPaths("ld", value)
		}
		return setText("ld", value)
	}
	input := ""
	if len(positional) == 0 && s.Input != "" && !visited["manifest-path"] {
		if input, err = path(s.Input); err != nil {
			return nil, err
		}
		positional = []string{input}
		if s.Cargo != nil && s.Cargo.ManifestPath != "" {
			return nil, usage("-settings %s: set input or cargo.manifest_path, not both", o.settings)
		}
	}
	steps := []func() error{
		func() error { return setText("target", s.Target) },
		func() error { return setText("package", s.Package) },
		func() error { return set("symbol", s.Symbols...) },
		func() error { return setBool("strip-debug", s.StripDebug) },
		func() error { return setPaths("link-archive", s.LinkArchives...) },
		func() error { return setPaths("link-notice", s.LinkNotices...) },
		func() error { return setBool("require-static-runtime", s.RequireStaticRuntime) },
	}
	// An explicit input means this run is not building the configured crate.
	if s.Cargo != nil && len(fs.Args()) == 0 && input == "" {
		steps = append(steps,
			func() error { return setPaths("manifest-path", s.Cargo.ManifestPath) },
			func() error { return setText("cargo-package", s.Cargo.Package) },
			func() error { return setBool("offline", s.Cargo.Offline) },
			func() error { return setBool("locked", s.Cargo.Locked) },
		)
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	if !visited["bindings"] {
		if err := o.applySettingsBindings(s.Bindings, path); err != nil {
			return nil, err
		}
	}
	// Only the section for this target applies, so one file can serve several.
	target, err := settingsTarget(o.target, positional)
	if err != nil {
		return nil, err
	}
	link := func(l platformLinkSettings) []func() error {
		return []func() error{
			func() error { return setPaths("link-archive", l.LinkArchives...) },
			func() error { return setPaths("link-notice", l.LinkNotices...) },
			func() error { return setBool("require-static-runtime", l.RequireStaticRuntime) },
		}
	}
	switch {
	case strings.HasPrefix(target, "darwin/") && s.Darwin != nil:
		steps = []func() error{
			func() error { return setPaths("sdk", s.Darwin.SDK) },
			func() error { return setText("min-os", s.Darwin.MinOS) },
			func() error { return setLinker(s.Darwin.Linker) },
		}
		steps = append(steps, link(s.Darwin.platformLinkSettings)...)
	case strings.HasPrefix(target, "linux/") && s.Linux != nil:
		steps = []func() error{
			func() error { return setPaths("sysroot", s.Linux.Sysroot) },
			func() error { return setLinker(s.Linux.Linker) },
			func() error { return set("linux-system-library", s.Linux.SystemLibraries...) },
		}
		steps = append(steps, link(s.Linux.platformLinkSettings)...)
	case strings.HasPrefix(target, "windows/") && s.Windows != nil:
		imports := make([]string, 0, len(s.Windows.Imports))
		for name, dll := range s.Windows.Imports {
			imports = append(imports, name+"="+dll)
		}
		sort.Strings(imports)
		steps = []func() error{
			func() error { return set("windows-import", imports...) },
			func() error { return setPaths("windows-import-library", s.Windows.ImportLibraries...) },
			func() error { return setText("windows-cxx-runtime", s.Windows.CXXRuntime) },
			func() error { return setText("windows-crt", s.Windows.CRT) },
			func() error {
				if s.Windows.MaxDataAlignment == nil {
					return nil
				}
				return set("windows-max-data-alignment", strconv.FormatUint(uint64(*s.Windows.MaxDataAlignment), 10))
			},
		}
		steps = append(steps, link(s.Windows.platformLinkSettings)...)
	default:
		steps = nil
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return positional, nil
}

// applySettingsBindings accepts a manifest path, "dwarf", or an inline manifest.
func (o *nativeFlags) applySettingsBindings(raw json.RawMessage, path func(string) (string, error)) error {
	if len(raw) == 0 {
		return nil
	}
	var reference string
	if err := json.Unmarshal(raw, &reference); err != nil {
		o.inlineBindings = raw
		return nil
	}
	if reference == "dwarf" {
		o.bindings = reference
		return nil
	}
	resolved, err := path(reference)
	if err != nil {
		return err
	}
	o.bindings = resolved
	return nil
}

// settingsTarget selects the platform section the way the command resolves its
// target: a native input decides, while Cargo builds use the requested target.
func settingsTarget(requested string, positional []string) (string, error) {
	input := ""
	if len(positional) == 1 {
		input = positional[0]
		if stat, err := os.Stat(input); err == nil && stat.IsDir() || filepath.Base(input) == "Cargo.toml" {
			input = ""
		}
	}
	if requested != "auto" {
		return requested, nil
	}
	target, _, err := resolveTarget(requested, input)
	if err != nil {
		return "", fmt.Errorf("-settings: %w", err)
	}
	return target.Name, nil
}
