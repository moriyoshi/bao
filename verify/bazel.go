package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
)

// BazelOptions selects the bounded local rules_go profile. Consumer Bazel
// definitions, Bazel 8.4.2, rules_go 0.65.0, the stock Go 1.26.10 SDK and the
// same-user host are trusted. ModuleRoots bind approved Go module names to local
// workspace-relative trees (including their BUILD files). External native
// repositories, custom build actions, cgo and nonstandard link modes are excluded.
type BazelOptions struct {
	Directory, Bazel, Target, Package, Output string
	Policy                                    Policy
	Envelopes                                 []Envelope
	ModuleRoots                               map[string]string
	Stdout, Stderr                            io.Writer
}

type bazelAction struct {
	Mnemonic             string   `json:"mnemonic"`
	Arguments            []string `json:"arguments"`
	EnvironmentVariables []struct {
		Key, Value string
	} `json:"environmentVariables"`
}

type bazelGraph struct {
	Actions []bazelAction `json:"actions"`
}

type bazelPackage struct {
	path   string
	inputs PackageInputs
	module string
}

// BazelBuild authenticates local source snapshots before Bazel loads them. It
// materializes only compilation_outputs using fresh private Bazel/Go state,
// checks actual link archives, and replays the one supported GoLink action with
// private archive copies. This does not use cmd/go's -toolexec mechanism.
func BazelBuild(ctx context.Context, o BazelOptions) (BuildReport, error) {
	var report BuildReport
	approved, err := Authenticate(o.Policy, o.Envelopes, o.Target)
	if err != nil {
		return report, err
	}
	parts := strings.Split(o.Target, "/")
	if len(parts) != 2 || !(parts[0] == "linux" && (parts[1] == "arm64" || parts[1] == "loong64" || parts[1] == "ppc64le") || parts[0] == "darwin" && (parts[1] == "arm64" || parts[1] == "amd64")) {
		return report, fmt.Errorf("Bazel verified-build supports Darwin arm64/amd64 and Linux arm64/loong64/ppc64le")
	}
	if !regexp.MustCompile(`^//[A-Za-z0-9_/.-]*:[A-Za-z0-9_.+-]+$`).MatchString(o.Package) || strings.Contains(o.Package, "..") {
		return report, fmt.Errorf("requires one explicit local Bazel //package:target label")
	}
	if len(approved) == 0 || len(approved) != len(o.ModuleRoots) {
		return report, fmt.Errorf("each approved native module requires one explicit local module root")
	}
	for module, root := range o.ModuleRoots {
		if _, ok := approved[module]; !ok || root == "." || !safePath(filepath.ToSlash(root)) || filepath.IsAbs(root) {
			return report, fmt.Errorf("invalid or unapproved local root %q for %s", root, module)
		}
		for other, r := range o.ModuleRoots {
			if other != module && (root == r || strings.HasPrefix(filepath.ToSlash(root)+"/", filepath.ToSlash(r)+"/")) {
				return report, fmt.Errorf("native module roots must not overlap")
			}
		}
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	bazel, err := exec.LookPath(o.Bazel)
	if err != nil {
		return report, err
	}
	bazel, err = filepath.Abs(bazel)
	if err != nil {
		return report, err
	}
	directory, err := filepath.EvalSymlinks(o.Directory)
	if err != nil {
		return report, err
	}
	work, err := os.MkdirTemp("", "bao-bazel-verified-")
	if err != nil {
		return report, err
	}
	work, err = filepath.EvalSymlinks(work)
	if err != nil {
		return report, err
	}
	defer func() {
		_ = filepath.WalkDir(work, func(p string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(p, 0700)
			}
			return nil
		})
		_ = os.RemoveAll(work)
	}()
	workspace := filepath.Join(work, "workspace")
	if err = bazelSnapshot(directory, workspace); err != nil {
		return report, err
	}
	for module, root := range o.ModuleRoots {
		files, err := Tree(filepath.Join(workspace, root), "")
		if err != nil {
			return report, err
		}
		if err = MatchTree(approved[module], files); err != nil {
			return report, err
		}
		report.Modules = append(report.Modules, module)
	}
	sort.Strings(report.Modules)
	if err = seal(workspace); err != nil {
		return report, err
	}
	// Nothing in the consumer's native trees is loaded by Bazel before the
	// complete authenticated copies above have been frozen.
	env := buildEnv(parts[0], parts[1], work)
	// rules_cc is an implicit rules_go dependency even for pure Go. Its
	// documented repository switch prevents macOS C compiler autodetection;
	// the deliberately invalid CC/CXX values stay in place.
	env = append(env, "BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=1")
	startup := []string{"--batch", "--ignore_all_rc_files", "--output_user_root=" + filepath.Join(work, "bazel")}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bazel, append(append([]string(nil), startup...), args...)...)
		cmd.Dir, cmd.Env, cmd.Stderr = workspace, env, o.Stderr
		b, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("Bazel %s: %w", strings.Join(args, " "), err)
		}
		return b, nil
	}
	b, err := run("version", "--gnu_format")
	if err != nil || strings.TrimSpace(string(b)) != "bazel 8.4.2" {
		return report, fmt.Errorf("Bazel profile requires Bazel 8.4.2: %s (%v)", strings.TrimSpace(string(b)), err)
	}
	common := []string{"--lockfile_mode=error", "--disk_cache=", "--remote_cache=", "--remote_executor=", "--noremote_accept_cached", "--noremote_upload_local_results", "--repository_cache=" + filepath.Join(work, "repository-cache"), "--spawn_strategy=sandboxed", "--genrule_strategy=sandboxed", "--symlink_prefix=/"}
	b, err = run(append([]string{"aquery", "--output=jsonproto", "deps(" + o.Package + ")"}, common...)...)
	if err != nil {
		return report, err
	}
	var graph bazelGraph
	if err = json.Unmarshal(b, &graph); err != nil {
		return report, err
	}
	link, packages, err := bazelCheckGraph(graph, workspace, o.Target, o.ModuleRoots)
	if err != nil {
		return report, err
	}
	b, err = run("info", "execution_root")
	if err != nil {
		return report, err
	}
	execroot := strings.TrimSpace(string(b))
	if !filepath.IsAbs(execroot) || !within(work, execroot) {
		return report, fmt.Errorf("Bazel execution root escaped private state")
	}
	if err = bazelToolchain(execroot, link); err != nil {
		return report, err
	}
	if err = bazelCheckTools(graph, link); err != nil {
		return report, err
	}
	if _, err = run(append([]string{"build", "--output_groups=compilation_outputs", o.Package}, common...)...); err != nil {
		return report, err
	}
	args, linkReport, err := bazelPrivateLink(execroot, work, link, packages)
	if err != nil {
		return report, err
	}
	for module := range approved {
		linked := false
		for _, pkg := range packages {
			_, present := linkReport.Archives[pkg.path]
			linked = linked || present && pkg.module == module && len(pkg.inputs.Native) != 0
		}
		if !linked {
			return report, fmt.Errorf("approved native module %s is absent from selected Bazel link inputs", module)
		}
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = execroot, env, o.Stdout, o.Stderr
	if err = cmd.Run(); err != nil {
		return report, fmt.Errorf("private Bazel GoLink replay: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(work, "executable"))
	if err != nil {
		return report, err
	}
	if err = WriteNew(o.Output, data, 0755); err != nil {
		return report, err
	}
	report.Target, report.OutputSHA256, report.Link = o.Target, Digest(data), linkReport
	report.Cache = "fresh private Bazel output/repository roots and Go caches; rc, disk/remote/action-result reuse excluded; private checked GoLink replay"
	return report, nil
}

func bazelSnapshot(source, target string) error {
	return filepath.WalkDir(source, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			// Bazel creates these convenience links in an ordinary workspace.
			// They are not source inputs, and a signed root containing one
			// will still fail complete-tree authentication.
			if filepath.Dir(rel) == "." && strings.HasPrefix(d.Name(), "bazel-") {
				return nil
			}
			return fmt.Errorf("symlink unsupported in Bazel source snapshot: %s", rel)
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(target, rel), 0700)
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported Bazel source file %s", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return WriteNew(filepath.Join(target, rel), b, 0400)
	})
}

func bazelValue(args []string, flag string) (string, error) {
	value, count := "", 0
	for i, arg := range args {
		if arg == flag {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing Bazel action value for %s", flag)
			}
			value, count = args[i+1], count+1
		}
	}
	if count != 1 || value == "" {
		return "", fmt.Errorf("requires one Bazel action %s", flag)
	}
	return value, nil
}

func bazelPath(root, path string) (string, error) {
	if filepath.IsAbs(path) || !safePath(filepath.ToSlash(path)) {
		return "", fmt.Errorf("Bazel action path escaped execution root: %q", path)
	}
	return filepath.Join(root, path), nil
}

func bazelCheckGraph(g bazelGraph, workspace, target string, roots map[string]string) (bazelAction, map[string]bazelPackage, error) {
	var link bazelAction
	packages := map[string]bazelPackage{}
	allowed := map[string]bool{"GoCompilePkg": true, "GoLink": true, "GoStdlib": true, "GoStdlibList": true, "GoToolchainBinaryBuild": true, "FileWrite": true, "ExecutableSymlink": true, "RepoMappingManifest": true, "SourceSymlinkManifest": true, "SymlinkTree": true, "Middleman": true}
	parts := strings.Split(target, "/")
	for _, a := range g.Actions {
		if !allowed[a.Mnemonic] {
			return link, nil, fmt.Errorf("unsupported Bazel action %s", a.Mnemonic)
		}
		if a.Mnemonic == "GoLink" {
			if len(link.Arguments) != 0 {
				return link, nil, fmt.Errorf("requires exactly one GoLink action")
			}
			if err := bazelLinkFlags(a.Arguments); err != nil {
				return link, nil, err
			}
			link = a
		}
		if a.Mnemonic != "GoCompilePkg" && a.Mnemonic != "GoLink" {
			continue
		}
		env := map[string]string{}
		for _, pair := range a.EnvironmentVariables {
			env[pair.Key] = pair.Value
		}
		if env["GOOS"] != parts[0] || env["GOARCH"] != parts[1] || env["CGO_ENABLED"] != "0" || env["GOEXPERIMENT"] != "" {
			return link, nil, fmt.Errorf("Bazel action must use the requested target, CGO_ENABLED=0, and stock Go experiments")
		}
		if bazelInstallSuffix(a.Arguments) != parts[0]+"_"+parts[1] {
			return link, nil, fmt.Errorf("unsupported Bazel Go install suffix")
		}
		if a.Mnemonic != "GoCompilePkg" {
			continue
		}
		if err := bazelCompileFlags(a.Arguments); err != nil {
			return link, nil, err
		}
		archive, err := bazelValue(a.Arguments, "-lo")
		if err != nil {
			return link, nil, err
		}
		pkg, err := bazelValue(a.Arguments, "-p")
		if err != nil {
			return link, nil, err
		}
		inputs := PackageInputs{Native: map[string][]string{}, GoMembers: map[string]int{"_go_.o": 1}}
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = parts[0], parts[1], false
		assembly, nativeRoot, nativeModule := 0, "", ""
		var sources []string
		for i, arg := range a.Arguments {
			if arg == "-tags" || strings.HasPrefix(arg, "-cgo") || arg == "-race" || arg == "-cover_mode" {
				return link, nil, fmt.Errorf("unsupported GoCompilePkg mode %s", arg)
			}
			if arg != "-src" || i+1 == len(a.Arguments) {
				continue
			}
			source := a.Arguments[i+1]
			path, err := bazelPath(workspace, source)
			if err != nil {
				return link, nil, err
			}
			sources = append(sources, path)
			if strings.HasSuffix(source, ".syso") {
				matched := ""
				for module, root := range roots {
					if within(filepath.Join(workspace, root), path) {
						matched = filepath.Join(workspace, root)
						nativeModule = module
					}
				}
				if matched == "" || nativeRoot != "" && nativeRoot != matched {
					return link, nil, fmt.Errorf("native Bazel input %s lacks one approved local module root", source)
				}
				nativeRoot = matched
				selected, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
				if err != nil {
					return link, nil, err
				}
				if !selected {
					continue
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return link, nil, err
				}
				inputs.Native[memberName(filepath.Base(source))] = append(inputs.Native[memberName(filepath.Base(source))], Digest(b))
			}
			if strings.HasSuffix(source, ".s") {
				// External rules_go helper packages may appear in analysis but
				// are not linked. Local signed assembly must be source-selected.
				ok, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
				if err != nil {
					return link, nil, err
				}
				if ok {
					inputs.GoMembers[fmt.Sprintf("s%d.o", assembly)] = 1
					assembly++
				}
			}
		}
		if nativeRoot != "" {
			if pkg != nativeModule && !strings.HasPrefix(pkg, nativeModule+"/") {
				return link, nil, fmt.Errorf("native package import path %s does not belong to approved module %s", pkg, nativeModule)
			}
			for _, path := range sources {
				if !within(nativeRoot, path) {
					return link, nil, fmt.Errorf("native package source escaped signed root: %s", path)
				}
			}
			var asm []string
			for _, path := range sources {
				if strings.HasSuffix(path, ".s") || strings.HasSuffix(path, ".h") {
					asm = append(asm, filepath.Base(path))
					if filepath.Dir(path) != filepath.Dir(sources[0]) {
						return link, nil, fmt.Errorf("nested signed assembly source directories unsupported")
					}
				}
			}
			if err := checkAssembly(filepath.Dir(sources[0]), asm); err != nil {
				return link, nil, err
			}
		}
		if _, duplicate := packages[archive]; duplicate {
			return link, nil, fmt.Errorf("duplicate Bazel compilation archive")
		}
		packages[archive] = bazelPackage{path: pkg, inputs: inputs, module: nativeModule}
	}
	if len(link.Arguments) == 0 {
		return link, nil, fmt.Errorf("missing Bazel GoLink action")
	}
	return link, packages, nil
}

func bazelCompileFlags(args []string) error {
	if len(args) < 3 || args[1] != "compilepkg" {
		return fmt.Errorf("unsupported rules_go GoCompilePkg command")
	}
	allowed := map[string]bool{"-sdk": true, "-goroot": true, "-installsuffix": true, "-src": true, "-arc": true, "-importpath": true, "-p": true, "-package_list": true, "-pack": true, "-embedroot": true, "-embedlookupdir": true, "-lo": true, "-o": true, "-imports": true, "-gcflags": true, "-asmflags": true}
	for i := 2; i < len(args); i += 2 {
		if !allowed[args[i]] || i+1 == len(args) {
			return fmt.Errorf("unsupported Bazel GoCompilePkg option %q", args[i])
		}
		if args[i] == "-gcflags" && args[i+1] != "" && !(bazelDarwinTarget(args) && args[i+1] == "-shared") || args[i] == "-asmflags" && !(bazelDarwinTarget(args) && args[i+1] == "-shared") {
			return fmt.Errorf("unsupported Bazel compiler or assembler flags")
		}
		if args[i] == "-src" {
			ext := filepath.Ext(args[i+1])
			if ext != ".go" && ext != ".s" && ext != ".h" && ext != ".syso" {
				return fmt.Errorf("unsupported Bazel native/compiler source %s", args[i+1])
			}
		}
	}
	return nil
}

func bazelLinkFlags(args []string) error {
	if len(args) < 3 || args[1] != "link" {
		return fmt.Errorf("unsupported rules_go GoLink command")
	}
	allowed := map[string]bool{"-sdk": true, "-goroot": true, "-installsuffix": true, "-arc": true, "-imports": true, "-package_list": true, "-o": true, "-main": true, "-main_package_path": true, "-main_imports": true, "-p": true, "-buildmode": true}
	for i := 2; i < len(args); i += 2 {
		if args[i] == "--" {
			if strings.Join(args[i+1:], " ") != "-linkmode internal -s -w" && strings.Join(args[i+1:], " ") != "-linkmode internal" {
				return fmt.Errorf("unsupported Bazel linker flags; requires ordinary pure internal linking")
			}
			return nil
		}
		if !allowed[args[i]] || i+1 == len(args) {
			return fmt.Errorf("unsupported Bazel GoLink option %q", args[i])
		}
		if args[i] == "-buildmode" && (!bazelDarwinTarget(args) || args[i+1] != "pie") {
			return fmt.Errorf("only Darwin's default PIE build mode is supported")
		}
	}
	return fmt.Errorf("missing pure internal-link flags")
}

func bazelToolchain(execroot string, link bazelAction) error {
	sdk, err := bazelValue(link.Arguments, "-sdk")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(sdk, "external/rules_go++go_sdk+") {
		return fmt.Errorf("requires the trusted rules_go SDK repository")
	}
	// Analysis has fetched repositories, but Bazel has not yet planted their
	// execroot symlinks (that happens when actions execute).
	repositories := filepath.Dir(filepath.Dir(execroot))
	path, err := bazelPath(repositories, sdk)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(path, "VERSION"))
	if err != nil || strings.SplitN(string(b), "\n", 2)[0] != "go1.26.10" {
		return fmt.Errorf("Bazel profile requires the stock Go 1.26.10 SDK: %v", err)
	}
	// Canonical repository naming is part of this deliberately small profile.
	b, err = os.ReadFile(filepath.Join(repositories, "external", "rules_go+", "MODULE.bazel"))
	if err != nil || !regexp.MustCompile(`version\s*=\s*"0\.65\.0"`).Match(b) {
		return fmt.Errorf("Bazel profile requires the trusted rules_go 0.65.0 repository")
	}
	return nil
}

func bazelCheckTools(g bazelGraph, link bazelAction) error {
	// A mnemonic is metadata, not an executable identity. In particular, a
	// publisher BUILD file must not run a native payload under a Go mnemonic.
	builder := link.Arguments[0]
	pattern := regexp.MustCompile(`^bazel-out/[A-Za-z0-9_-]+/bin/external/rules_go\+\+go_sdk\+[A-Za-z0-9_+-]+/builder_reset/builder$`)
	if !pattern.MatchString(builder) {
		return fmt.Errorf("unsupported rules_go builder executable")
	}
	sdk, _ := bazelValue(link.Arguments, "-sdk")
	stdlib, _ := bazelValue(link.Arguments, "-goroot")
	if !regexp.MustCompile(`^bazel-out/[A-Za-z0-9_-]+/bin/external/rules_go\+/stdlib_$`).MatchString(stdlib) {
		return fmt.Errorf("unsupported rules_go standard-library output")
	}
	for _, a := range g.Actions {
		environment := map[string]string{}
		for _, pair := range a.EnvironmentVariables {
			if _, duplicate := environment[pair.Key]; duplicate {
				return fmt.Errorf("duplicate Bazel action environment variable")
			}
			environment[pair.Key] = pair.Value
		}
		switch a.Mnemonic {
		case "GoCompilePkg", "GoLink", "GoStdlib", "GoStdlibList":
			if len(a.Arguments) < 2 || a.Arguments[0] != builder {
				return fmt.Errorf("Bazel Go action does not use the inspected trusted builder")
			}
			other, err := bazelValue(a.Arguments, "-sdk")
			if err != nil || other != sdk {
				return fmt.Errorf("Bazel Go actions must share one trusted SDK")
			}
			allowedEnv := map[string]bool{"GOOS": true, "GOARCH": true, "CGO_ENABLED": true, "GOEXPERIMENT": true, "GOROOT": true, "GOROOT_FINAL": true, "GOPATH": true, "GOTOOLCHAIN": true, "GODEBUG": true}
			for key := range environment {
				if !allowedEnv[key] {
					return fmt.Errorf("unsupported Bazel Go action environment variable %s", key)
				}
			}
			if environment["CGO_ENABLED"] != "0" || environment["GOEXPERIMENT"] != "" || environment["GOTOOLCHAIN"] != "local" || environment["GOPATH"] != "" || environment["GOROOT_FINAL"] != "GOROOT" {
				return fmt.Errorf("unsupported Bazel Go action environment")
			}
			root, err := bazelValue(a.Arguments, "-goroot")
			if err != nil {
				return err
			}
			if a.Mnemonic == "GoCompilePkg" || a.Mnemonic == "GoLink" {
				if root != stdlib {
					return fmt.Errorf("Bazel Go actions must use the inspected standard library")
				}
			}
			if a.Mnemonic == "GoCompilePkg" {
				pack, err := bazelValue(a.Arguments, "-pack")
				if err != nil || !regexp.MustCompile(`^bazel-out/[A-Za-z0-9_-]+/bin/`+regexp.QuoteMeta(sdk)+`/pack_reset/pack\.exe$`).MatchString(pack) {
					return fmt.Errorf("unsupported rules_go archive packer")
				}
			}
			if a.Mnemonic == "GoStdlib" || a.Mnemonic == "GoStdlibList" {
				if root != sdk {
					return fmt.Errorf("standard-library bootstrap must use trusted SDK sources and tools")
				}
				allowed := map[string]bool{"-sdk": true, "-goroot": true, "-installsuffix": true, "-out": true, "-package": true, "-gcflags": true, "-cache": true}
				if (a.Mnemonic == "GoStdlib" && a.Arguments[1] != "stdlib") || (a.Mnemonic == "GoStdlibList" && a.Arguments[1] != "stdliblist") {
					return fmt.Errorf("unsupported Go standard-library action")
				}
				for i := 2; i < len(a.Arguments); i += 2 {
					if a.Arguments[i] == "-shared" && bazelDarwinTarget(a.Arguments) {
						i-- // A boolean argument, emitted for Darwin's default PIE.
						continue
					}
					if i+1 == len(a.Arguments) || !allowed[a.Arguments[i]] || a.Arguments[i] == "-gcflags" && a.Arguments[i+1] != "" {
						return fmt.Errorf("unsupported Go standard-library flags")
					}
				}
				for _, pair := range a.EnvironmentVariables {
					if pair.Key == "CGO_ENABLED" && pair.Value != "0" || pair.Key == "GOEXPERIMENT" && pair.Value != "" {
						return fmt.Errorf("unsupported Go standard-library environment")
					}
				}
			}
		case "GoToolchainBinaryBuild":
			allowedEnv := map[string]bool{"GOMAXPROCS": true, "GOTOOLCHAIN": true, "GO111MODULE": true, "GOTELEMETRY": true, "GOENV": true, "GOEXPERIMENT": true, "GO_BINARY": true, "LD_FLAGS": true}
			for key := range environment {
				if !allowedEnv[key] {
					return fmt.Errorf("unsupported Go bootstrap environment variable %s", key)
				}
			}
			if environment["GO_BINARY"] != sdk+"/bin/go" || environment["LD_FLAGS"] != "-X main.rulesGoStdlibPrefix=@@rules_go+//stdlib:" || environment["GOENV"] != "off" || environment["GOTOOLCHAIN"] != "local" || environment["GO111MODULE"] != "off" || environment["GOEXPERIMENT"] != "" || environment["GOMAXPROCS"] != "1" || environment["GOTELEMETRY"] != "off" {
				return fmt.Errorf("Go bootstrap environment can replace trusted tools or flags")
			}
			if len(a.Arguments) < 5 || a.Arguments[0] != "external/rules_go+/go/private/rules/binary_wrapper.sh" {
				return fmt.Errorf("unsupported Go toolchain bootstrap executable")
			}
			for i, output := range a.Arguments[1:4] {
				name := []string{"pack.exe", "covdata.exe", "builder"}[i]
				if !regexp.MustCompile(`^bazel-out/[A-Za-z0-9_-]+/bin/` + regexp.QuoteMeta(sdk) + `/` + regexp.QuoteMeta(name) + `$`).MatchString(output) {
					return fmt.Errorf("Go toolchain bootstrap output escaped SDK repository")
				}
			}
			for _, source := range a.Arguments[4:] {
				if !strings.HasPrefix(source, "external/rules_go+/go/tools/builders/") || !strings.HasSuffix(source, ".go") || strings.Contains(source, "..") {
					return fmt.Errorf("Go toolchain bootstrap source escaped trusted rules_go")
				}
			}
		}
	}
	return nil
}

// bazelCheckArchive is separate from CheckArchive: rules_go splits export data
// into a .x file, and its link .a has zero PKGDEF records and sN.o assembly names.
func bazelCheckArchive(data []byte, expected PackageInputs, target string) (int, error) {
	members, err := ar.Parse(data)
	if err != nil {
		return 0, err
	}
	want := map[string]map[string]int{}
	for name, hashes := range expected.Native {
		want[name] = map[string]int{}
		for _, hash := range hashes {
			want[name][hash]++
		}
	}
	seen, native := map[string]int{}, 0
	header := []byte("go object " + strings.ReplaceAll(target, "/", " ") + " go1.26.10 ")
	for _, member := range members {
		hash := Digest(member.Data)
		if want[member.Name][hash] > 0 {
			want[member.Name][hash]--
			native++
			continue
		}
		if expected.GoMembers[member.Name] <= seen[member.Name] || !bytes.HasPrefix(member.Data, header) {
			return 0, fmt.Errorf("unexpected or substituted rules_go archive member %q", member.Name)
		}
		seen[member.Name]++
	}
	if expected.GoMembers["_go_.o"] != 1 {
		return 0, fmt.Errorf("rules_go archive profile requires one Go object")
	}
	for name, count := range expected.GoMembers {
		if seen[name] != count {
			return 0, fmt.Errorf("missing rules_go object %s", name)
		}
	}
	for name, hashes := range want {
		for _, count := range hashes {
			if count != 0 {
				return 0, fmt.Errorf("missing signed rules_go native member %s", name)
			}
		}
	}
	return native, nil
}

func bazelPrivateLink(execroot, work string, link bazelAction, packages map[string]bazelPackage) ([]string, LinkReport, error) {
	report := LinkReport{Archives: map[string]string{}}
	args := append([]string(nil), link.Arguments...)
	private := filepath.Join(work, "link-inputs")
	if err := os.Mkdir(private, 0700); err != nil {
		return nil, report, err
	}
	copyFile := func(source, destination string, mode os.FileMode) error {
		b, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		return WriteNew(destination, b, mode)
	}
	copyArchive := func(path string) (string, error) {
		pkg, ok := packages[path]
		if !ok {
			return "", fmt.Errorf("link archive %s has no inspected GoCompilePkg action", path)
		}
		source, err := bazelPath(execroot, path)
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(source)
		if err != nil {
			return "", err
		}
		n, err := bazelCheckArchive(b, pkg.inputs, strings.ReplaceAll(bazelInstallSuffix(args), "_", "/"))
		if err != nil {
			return "", fmt.Errorf("Bazel archive %s: %w", pkg.path, err)
		}
		if _, exists := report.Archives[pkg.path]; exists {
			return "", fmt.Errorf("duplicate linked Bazel package %s", pkg.path)
		}
		report.Archives[pkg.path] = Digest(b)
		report.NativeMembers += n
		destination := filepath.Join(private, fmt.Sprintf("%04d.a", len(report.Archives)))
		return destination, WriteNew(destination, b, 0400)
	}
	for i := 2; i < len(args) && args[i] != "--"; i += 2 {
		value := args[i+1]
		switch args[i] {
		case "-arc":
			fields := strings.SplitN(value, "=", 3)
			if len(fields) != 3 {
				return nil, report, fmt.Errorf("invalid rules_go archive argument")
			}
			if pkg, ok := packages[fields[2]]; !ok || pkg.path != fields[1] {
				return nil, report, fmt.Errorf("Bazel link import mapping differs from inspected compilation")
			}
			path, err := copyArchive(fields[2])
			if err != nil {
				return nil, report, err
			}
			args[i+1] = fields[0] + "=" + fields[1] + "=" + path
		case "-main":
			path, err := copyArchive(value)
			if err != nil {
				return nil, report, err
			}
			args[i+1] = path
		case "-goroot":
			source, err := bazelPath(execroot, value)
			if err != nil {
				return nil, report, err
			}
			root := filepath.Join(private, "goroot")
			err = filepath.WalkDir(filepath.Join(source, "pkg"), func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(path, ".a") {
					return err
				}
				rel, err := filepath.Rel(source, path)
				if err != nil {
					return err
				}
				return copyFile(path, filepath.Join(root, rel), 0400)
			})
			if err != nil {
				return nil, report, err
			}
			args[i+1] = root
		case "-sdk":
			source, err := bazelPath(execroot, value)
			if err != nil {
				return nil, report, err
			}
			tool, err := filepath.Glob(filepath.Join(source, "pkg", "tool", "*", "link"))
			if err != nil || len(tool) != 1 {
				return nil, report, fmt.Errorf("requires one trusted host SDK linker")
			}
			rel, _ := filepath.Rel(source, tool[0])
			root := filepath.Join(private, "sdk")
			if err = copyFile(tool[0], filepath.Join(root, rel), 0500); err != nil {
				return nil, report, err
			}
			args[i+1] = root
		case "-imports", "-main_imports", "-package_list":
			prefix, path := "", value
			if args[i] == "-imports" {
				var ok bool
				prefix, path, ok = strings.Cut(value, "=")
				if !ok {
					return nil, report, fmt.Errorf("invalid rules_go imports argument")
				}
				prefix += "="
			}
			source, err := bazelPath(execroot, path)
			if err != nil {
				return nil, report, err
			}
			destination := filepath.Join(private, fmt.Sprintf("metadata-%d", i))
			if err = copyFile(source, destination, 0400); err != nil {
				return nil, report, err
			}
			args[i+1] = prefix + destination
		case "-o":
			args[i+1] = filepath.Join(work, "executable")
		}
	}
	builder, err := bazelPath(execroot, args[0])
	if err != nil {
		return nil, report, err
	}
	args[0] = filepath.Join(private, "builder")
	if err = copyFile(builder, args[0], 0500); err != nil {
		return nil, report, err
	}
	return args, report, nil
}

func bazelInstallSuffix(args []string) string {
	suffix, _ := bazelValue(args, "-installsuffix")
	return suffix
}

func bazelDarwinTarget(args []string) bool {
	suffix := bazelInstallSuffix(args)
	return suffix == "darwin_arm64" || suffix == "darwin_amd64"
}
