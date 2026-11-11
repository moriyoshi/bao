package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/scanner"
)

type BuildOptions struct {
	Directory, Go, Bao, Target, Output, Package string
	Policy                                      Policy
	Envelopes                                   []Envelope
	Stdout, Stderr                              io.Writer
}
type Module struct {
	Path, Dir string
	Main      bool
	Replace   *Module
}
type Package struct {
	ImportPath, Dir, Name      string
	Standard                   bool
	Module                     *Module
	GoFiles, SFiles, SysoFiles []string
}
type PackageInputs struct {
	Native    map[string][]string `json:"native"` // truncated ar member name -> SHA256 multiset
	GoMembers map[string]int      `json:"go_members"`
}
type HookConfig struct {
	Schema        int                      `json:"schema"`
	ToolDirectory string                   `json:"tool_directory"`
	Private       string                   `json:"private"`
	Packages      map[string]PackageInputs `json:"packages"`
	Main          string                   `json:"main"`
}
type BuildReport struct {
	Target       string     `json:"target"`
	OutputSHA256 string     `json:"output_sha256"`
	Modules      []string   `json:"authenticated_modules"`
	Cache        string     `json:"cache"`
	Link         LinkReport `json:"link"`
}

// Build always starts from private source copies and an empty private cache.
// Its trusted toolexec hook binds the actual archive bytes to linker inputs.
// This profile assumes a trusted same-user host, Bao binary, policy and Go SDK.
func Build(ctx context.Context, o BuildOptions) (BuildReport, error) {
	var report BuildReport
	var err error
	o.Directory, err = filepath.EvalSymlinks(o.Directory)
	if err != nil {
		return report, err
	}
	approved, err := Authenticate(o.Policy, o.Envelopes, o.Target)
	if err != nil {
		return report, err
	}
	parts := strings.Split(o.Target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return report, fmt.Errorf("invalid target")
	}
	if o.Package == "" {
		o.Package = "."
	}
	if strings.HasPrefix(o.Package, "-") || strings.Contains(o.Package, "...") || strings.ContainsAny(o.Package, "\r\n\x00") {
		return report, fmt.Errorf("one main package selector required")
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	goTool, err := exec.LookPath(o.Go)
	if err != nil {
		return report, err
	}
	goTool, err = filepath.Abs(goTool)
	if err != nil {
		return report, err
	}
	bao, err := filepath.Abs(o.Bao)
	if err != nil {
		return report, err
	}
	// Go's -toolexec uses its own quoted command-line parser. Quote the trusted
	// executable; config travels in the scrubbed environment, never a shell.
	if strings.ContainsAny(bao, "\"'\r\n") {
		return report, fmt.Errorf("Bao executable path contains unsupported quoting")
	}
	work, err := os.MkdirTemp("", "bao-verified-")
	if err != nil {
		return report, err
	}
	work, err = filepath.EvalSymlinks(work)
	if err != nil {
		return report, err
	}
	defer func() {
		// Snapshot directories are read-only during the build; restore owner
		// traversal/write permission only for removal after all tools exit.
		_ = filepath.WalkDir(work, func(p string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(p, 0700)
			}
			return nil
		})
		_ = os.RemoveAll(work)
	}()
	env := buildEnv(parts[0], parts[1], work)
	run := func(dir string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, goTool, args...)
		cmd.Dir = dir
		cmd.Env = env
		cmd.Stderr = o.Stderr
		b, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
		}
		return b, nil
	}
	b, err := run(o.Directory, "env", "-json", "GOROOT", "GOVERSION", "GOTOOLDIR")
	if err != nil {
		return report, err
	}
	var ge map[string]string
	if err = Decode(b, &ge); err != nil {
		return report, err
	}
	if ge["GOVERSION"] != "go1.26.11" {
		return report, fmt.Errorf("verified-build profile requires stock Go 1.26.11, got %s", ge["GOVERSION"])
	}
	// Resolve without compiling or executing any consumer init/main. Dependencies
	// must be downloaded beforehand; no network or toolchain download is allowed.
	b, err = run(o.Directory, "list", "-mod=readonly", "-deps", "-json", o.Package)
	if err != nil {
		return report, err
	}
	packages, err := decodePackages(b)
	if err != nil {
		return report, err
	}
	modules := map[string]*Module{}
	mainModule := ""
	for _, p := range packages {
		if p.Module != nil {
			modules[p.Module.Path] = p.Module
			if p.Module.Main {
				mainModule = p.Module.Path
			}
		}
	}
	if mainModule == "" {
		return report, fmt.Errorf("requires a module main package; workspaces and GOPATH builds are outside this profile")
	}
	keys := make([]string, 0, len(modules))
	for k := range modules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snapshots := map[string]string{}
	for i, k := range keys {
		m := modules[k]
		dir := m.Dir
		if m.Replace != nil {
			dir = m.Replace.Dir
		}
		if dir == "" {
			return report, fmt.Errorf("module %s has no resolved source directory", k)
		}
		dst := filepath.Join(work, fmt.Sprintf("module-%d", i))
		files, err := Tree(dir, dst)
		if err != nil {
			return report, err
		}
		if manifest, ok := approved[k]; ok {
			if err = MatchTree(manifest, files); err != nil {
				return report, err
			}
			report.Modules = append(report.Modules, k)
		}
		snapshots[k] = dst
	}
	for k := range approved {
		if snapshots[k] == "" {
			return report, fmt.Errorf("approved native module %s is absent from selected dependency closure", k)
		}
	}
	mainDir := snapshots[mainModule]
	// Change only dependency resolution in the private main go.mod, after hashing
	// the original bytes. Each selected module resolves to its verified copy.
	mod := filepath.Join(mainDir, "go.mod")
	if err = os.Chmod(mod, 0600); err != nil {
		return report, err
	}
	args := []string{"mod", "edit"}
	for _, k := range keys {
		if k != mainModule {
			args = append(args, "-replace="+k+"="+snapshots[k])
		}
	}
	if len(args) > 2 {
		if _, err = run(mainDir, args...); err != nil {
			return report, err
		}
	}
	// Local selectors are relative to the invocation directory within its module.
	originalMain := modules[mainModule].Dir
	rel, err := filepath.Rel(originalMain, o.Directory)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return report, fmt.Errorf("invocation must be within main module")
	}
	buildDir := filepath.Join(mainDir, rel)
	b, err = run(buildDir, "list", "-mod=readonly", "-deps", "-json", o.Package)
	if err != nil {
		return report, err
	}
	packages, err = decodePackages(b)
	if err != nil {
		return report, err
	}
	config := HookConfig{Schema: 1, ToolDirectory: ge["GOTOOLDIR"], Private: work, Packages: map[string]PackageInputs{}}
	for _, p := range packages {
		if !p.Standard {
			if p.Module == nil || snapshots[p.Module.Path] == "" || !within(snapshots[p.Module.Path], p.Dir) {
				return report, fmt.Errorf("package %s escaped source snapshots", p.ImportPath)
			}
			if err = checkAssembly(p.Dir, p.SFiles); err != nil {
				return report, err
			}
		}
		inputs := PackageInputs{Native: map[string][]string{}, GoMembers: map[string]int{"_go_.o": 1}}
		for _, s := range p.SFiles {
			inputs.GoMembers[memberName(strings.TrimSuffix(s, filepath.Ext(s))+".o")]++
		}
		for _, s := range p.SysoFiles {
			if p.Standard {
				return report, fmt.Errorf("standard-library native objects are outside the initial verified-build profile")
			}
			if _, ok := approved[p.Module.Path]; !ok {
				return report, fmt.Errorf("selected native input %s/%s lacks an approved signed module", p.ImportPath, s)
			}
			data, err := os.ReadFile(filepath.Join(p.Dir, s))
			if err != nil {
				return report, err
			}
			inputs.Native[memberName(s)] = append(inputs.Native[memberName(s)], Digest(data))
		}
		config.Packages[p.ImportPath] = inputs
		if p.Name == "main" && p.ImportPath == packages[len(packages)-1].ImportPath {
			config.Main = p.ImportPath
		}
	}
	if config.Main == "" {
		return report, fmt.Errorf("selected package is not an executable main")
	}
	for _, dir := range snapshots {
		if err = seal(dir); err != nil {
			return report, err
		}
	}
	configPath := filepath.Join(work, "hook.json")
	b, _ = json.Marshal(config)
	if err = WriteNew(configPath, b, 0400); err != nil {
		return report, err
	}
	env = append(env, "BAO_VERIFY_CONFIG="+configPath)
	output := filepath.Join(work, "executable")
	if _, err = run(buildDir, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-toolexec=\""+bao+"\" _verified-tool", "-ldflags=-linkmode=internal", "-o", output, o.Package); err != nil {
		return report, err
	}
	b, err = os.ReadFile(filepath.Join(work, "link-report.json"))
	if err != nil {
		return report, fmt.Errorf("required linker verification did not run: %w", err)
	}
	if err = Decode(b, &report.Link); err != nil {
		return report, err
	}
	data, err := os.ReadFile(output)
	if err != nil {
		return report, err
	}
	if err = WriteNew(o.Output, data, 0755); err != nil {
		return report, err
	}
	report.Target = o.Target
	report.OutputSHA256 = Digest(data)
	report.Cache = "fresh private GOCACHE per request; shared build caches and link cache hits excluded"
	return report, nil
}

func decodePackages(b []byte) ([]Package, error) {
	var out []Package
	d := json.NewDecoder(bytes.NewReader(b))
	for {
		var p Package
		err := d.Decode(&p)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
}
// memberName is the archive member name that cmd/go and cmd/pack 1.26.11 give
// file s: names are truncated to 16 bytes, but a long .syso name keeps its
// suffix (first 11 bytes plus ".syso"). Generated native names are ASCII, so
// cmd/go's byte truncation and cmd/pack's rune truncation agree.
func memberName(s string) string {
	if len(s) > 16 && strings.HasSuffix(s, ".syso") {
		return s[:16-len(".syso")] + ".syso"
	}
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
func within(root, p string) bool {
	r, e := filepath.Rel(root, p)
	return e == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func seal(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0400)
		if d.IsDir() {
			mode = 0500
		}
		return os.Chmod(p, mode)
	})
}

func checkAssembly(dir string, files []string) error {
	// No arbitrary preprocessor paths outside signed snapshots. Nested headers
	// are checked too, including otherwise unused headers in selected packages.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".h") {
			files = append(files, e.Name())
		}
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return err
		}
		// Tokenize comments and whitespace rather than matching source lines:
		// '# /*comment*/ include' must not bypass the path restriction.
		var scan scanner.Scanner
		scan.Init(bytes.NewReader(b))
		scan.Error = func(*scanner.Scanner, string) {}
		scan.Mode = scanner.ScanIdents | scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanComments | scanner.SkipComments
		for token := scan.Scan(); token != scanner.EOF; token = scan.Scan() {
			if token != '#' {
				continue
			}
			if scan.Scan() != scanner.Ident || scan.TokenText() != "include" {
				continue
			}
			if scan.Scan() != scanner.String {
				return fmt.Errorf("unsupported assembly include in %s", f)
			}
			s, err := strconv.Unquote(scan.TokenText())
			if err != nil || !safePath(s) || strings.Contains(s, "/") {
				return fmt.Errorf("assembly include escapes package in %s", f)
			}
		}
	}
	return nil
}

func buildEnv(goos, arch, work string) []string {
	// Do not inherit GOFLAGS, GOEXPERIMENT, GOENV, overlays, GO_EXTLINK_ENABLED,
	// compiler/linker flags, cache programs, toolexec, or module/toolchain proxies.
	var env []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "GOMODCACHE", "GOPATH"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	env = append(env, "GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTELEMETRY=off", "CGO_ENABLED=0", "CC=bao-verified-no-c-compiler", "CXX=bao-verified-no-cxx-compiler", "RUSTC=bao-verified-no-rust-compiler", "GOOS="+goos, "GOARCH="+arch, "GOCACHE="+filepath.Join(work, "cache"), "GOTMPDIR="+work)
	if arch == "amd64" {
		env = append(env, "GOAMD64=v1")
	}
	if arch == "ppc64le" {
		env = append(env, "GOPPC64=power8")
	}
	return env
}
