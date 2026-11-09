package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/verify"
)

// buildConfig is the -config file. Every field mirrors a command-line flag.
// Paths are relative to the file and may use ${VAR}; an unset variable fails.
type buildConfig struct {
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
		platformLinkConfig
		SDK    string `json:"sdk"`
		MinOS  string `json:"min_os"`
		Linker string `json:"ld"`
	} `json:"darwin"`
	Linux *struct {
		platformLinkConfig
		Sysroot         string   `json:"sysroot"`
		Linker          string   `json:"ld"`
		SystemLibraries []string `json:"system_libraries"`
	} `json:"linux"`
	Windows *struct {
		platformLinkConfig
		Imports          map[string]string `json:"imports"`
		ImportLibraries  []string          `json:"import_libraries"`
		CXXRuntime       string            `json:"cxx_runtime"`
		CRT              string            `json:"crt"`
		MaxDataAlignment *uint             `json:"max_data_alignment"`
	} `json:"windows"`
}

// platformLinkConfig adds to the common link config for one platform.
type platformLinkConfig struct {
	LinkArchives         []string `json:"link_archives"`
	LinkNotices          []string `json:"link_notices"`
	RequireStaticRuntime *bool    `json:"require_static_runtime"`
}

// defaultConfigFile applies from the working directory unless -config is given.
const defaultConfigFile = ".bao.config.json"

var configVariable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// applyConfig fills flags the command line left unset and returns the
// positional arguments. A flag given on the command line replaces its setting,
// including every entry of a repeatable flag.
func (o *nativeFlags) applyConfig(fs *flag.FlagSet, stderr io.Writer) ([]string, error) {
	positional := fs.Args()
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	// An unreadable default file is reported below instead of being skipped.
	if _, err := os.Stat(defaultConfigFile); !visited["config"] && !errors.Is(err, os.ErrNotExist) {
		o.config = defaultConfigFile
		fmt.Fprintf(stderr, "Using config from %s\n", defaultConfigFile)
	}
	if o.config == "" {
		return positional, nil
	}
	data, err := os.ReadFile(o.config)
	if err != nil {
		return nil, err
	}
	var s buildConfig
	if err := verify.Decode(data, &s); err != nil {
		return nil, usage("-config %s: %v", o.config, err)
	}
	if s.Schema != 1 {
		return nil, usage("-config %s: unsupported schema %d; expected 1", o.config, s.Schema)
	}
	dir, err := filepath.Abs(filepath.Dir(o.config))
	if err != nil {
		return nil, err
	}
	// Target variables take precedence over the environment. The input decides
	// an auto target, so they are unavailable until the target is known.
	var targetVariables map[string]string
	path := func(value string) (string, error) {
		var missing string
		value = configVariable.ReplaceAllStringFunc(value, func(match string) string {
			name := configVariable.FindStringSubmatch(match)[1]
			if expanded, ok := targetVariables[name]; ok {
				return expanded
			}
			expanded, ok := os.LookupEnv(name)
			if !ok {
				missing = name
			}
			return expanded
		})
		if missing != "" {
			if strings.HasPrefix(missing, "BAO_") && targetVariables == nil {
				return "", usage("-config %s: %s is not available in input, which decides the target", o.config, missing)
			}
			return "", usage("-config %s: environment variable %s is not set", o.config, missing)
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
			return usage("-config %s: the -%s setting does not apply to bao %s", o.config, name, fs.Name())
		}
		for _, value := range values {
			if err := fs.Set(name, value); err != nil {
				return usage("-config %s: -%s: %v", o.config, name, err)
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
		if strings.ContainsRune(value, filepath.Separator) || configVariable.MatchString(value) {
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
			return nil, usage("-config %s: set input or cargo.manifest_path, not both", o.config)
		}
	}
	if err := setText("target", s.Target); err != nil {
		return nil, err
	}
	target, err := configTarget(o.target, positional)
	if err != nil {
		return nil, err
	}
	targetVariables = configTargetVariables(target)
	steps := []func() error{
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
		if err := o.applyConfigBindings(s.Bindings, path); err != nil {
			return nil, err
		}
	}
	// Only the section for this target applies, so one file can serve several.
	link := func(l platformLinkConfig) []func() error {
		return []func() error{
			func() error { return setPaths("link-archive", l.LinkArchives...) },
			func() error { return setPaths("link-notice", l.LinkNotices...) },
			func() error { return setBool("require-static-runtime", l.RequireStaticRuntime) },
		}
	}
	switch {
	case strings.HasPrefix(target.Name, "darwin/") && s.Darwin != nil:
		steps = []func() error{
			func() error { return setPaths("sdk", s.Darwin.SDK) },
			func() error { return setText("min-os", s.Darwin.MinOS) },
			func() error { return setLinker(s.Darwin.Linker) },
		}
		steps = append(steps, link(s.Darwin.platformLinkConfig)...)
	case strings.HasPrefix(target.Name, "linux/") && s.Linux != nil:
		steps = []func() error{
			func() error { return setPaths("sysroot", s.Linux.Sysroot) },
			func() error { return setLinker(s.Linux.Linker) },
			func() error { return set("linux-system-library", s.Linux.SystemLibraries...) },
		}
		steps = append(steps, link(s.Linux.platformLinkConfig)...)
	case strings.HasPrefix(target.Name, "windows/") && s.Windows != nil:
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
		steps = append(steps, link(s.Windows.platformLinkConfig)...)
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

// applyConfigBindings accepts a manifest path, "dwarf", or an inline manifest.
func (o *nativeFlags) applyConfigBindings(raw json.RawMessage, path func(string) (string, error)) error {
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

// configTargetVariables names the build target for paths in a config file.
func configTargetVariables(target toolchain.Target) map[string]string {
	goos, goarch, _ := strings.Cut(target.Name, "/")
	cpu, _, _ := strings.Cut(target.RustTriple, "-")
	return map[string]string{"BAO_GOOS": goos, "BAO_GOARCH": goarch, "BAO_CPU": cpu}
}

// configTarget resolves the target the way the command does: a native input
// decides, while Cargo builds use the requested target or the host.
func configTarget(requested string, positional []string) (toolchain.Target, error) {
	input := ""
	if len(positional) == 1 {
		input = positional[0]
		if stat, err := os.Stat(input); err == nil && stat.IsDir() || filepath.Base(input) == "Cargo.toml" {
			input = ""
		}
	}
	if requested != "auto" {
		target, err := toolchain.ParseTarget(requested)
		if err != nil {
			return target, usage("%v", err)
		}
		return target, nil
	}
	target, _, err := resolveTarget(requested, input)
	if err != nil {
		return target, fmt.Errorf("-config: %w", err)
	}
	return target, nil
}
