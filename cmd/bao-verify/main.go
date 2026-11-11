// bao-verify runs explicit producer/consumer integration checks without Python.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const puregoModule = "github.com/ebitengine/purego"
const puregoVersion = "v0.11.3"
const puregoSum = "h1:OB+JLpdm7ioymhyA+6s5kbb/uOuYycAgL8NNTFc5MLg="
const linuxImage = "rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd"

type verifyFailure struct{ err error }

func require(err error) {
	if err != nil {
		panic(verifyFailure{err})
	}
}
func check(ok bool, format string, args ...any) {
	if !ok {
		require(fmt.Errorf(format, args...))
	}
}

type harness struct {
	staticRuntimeRoot                                     string
	staticLinkArchives, staticLinkNotices                 []string
	staticWindows                                         bool
	staticWindowsCRT                                      string
	windowsDriver                                         string
	windowsDLLDir                                         string
	ctx                                                   context.Context
	root, work, dst, bao, goTool, image, gpui, bazel, cxx string
	target                                                string
	env                                                   map[string]string
	onlineProxy, onlineSumDB                              string
	results                                               map[string]any
	windowsCC, windowsCXX, windowsAR, windowsRunner       string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := verify(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bao-verify:", err)
		os.Exit(1)
	}
}

func verify(ctx context.Context, args []string) (err error) {
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(verifyFailure); ok {
				err = f.err
			} else {
				panic(v)
			}
		}
	}()
	flags := flag.NewFlagSet("bao-verify", flag.ContinueOnError)
	suite := flags.String("suite", "darwin", "darwin, cpp, tls, linux, linux-cross, bindings, signatures, bazel, release-smoke, windows, static, gpui, or all")
	staticRuntimeRoot := flags.String("static-runtime-root", "", "static runtime prefix for the selected Darwin/Windows producer")
	root := flags.String("root", os.Getenv("BUILD_WORKSPACE_DIRECTORY"), "Bao source workspace; defaults to Bazel workspace or current directory")
	bao := flags.String("bao", "", "Bao executable; provided automatically by Bazel")
	goTool := flags.String("go", "go", "Go executable; provided automatically by Bazel")
	bazel := flags.String("bazel", "bazel", "trusted Bazel 8.4.2 executable for the bazel consumer suite")
	image := flags.String("image", linuxImage, "Docker producer/execution image; Linux C++ defaults to the pinned GCC image")
	cxx := flags.String("cxx", "g++", "Linux C++ compiler inside Docker: g++ or clang++; Clang requires an explicit -image")
	windowsCC := flags.String("windows-cc", "clang", "Windows COFF C producer compiler")
	windowsDriver := flags.String("windows-driver", "clang", "Windows producer: clang, clang-cl, msvc, or mingw")
	windowsCXX := flags.String("windows-cxx", "clang++", "Windows COFF C++ producer compiler")
	windowsAR := flags.String("windows-ar", "llvm-ar", "Windows archive producer")
	windowsRunner := flags.String("windows-runner", "", "optional local Wine wrapper; omission requires native Windows")
	windowsDLLDir := flags.String("windows-dll-dir", "", "directory containing matching GNU C++ runtime DLLs for the Windows integration consumer")
	gpui := flags.String("gpui-root", "", "optional GPUI checkout, required only for -suite gpui")
	target := flags.String("target", runtime.GOOS+"/"+runtime.GOARCH, "native target; Darwin amd64 on arm64 uses Rosetta; Linux C++ uses Docker")
	evidence := flags.String("evidence", "", "new directory for compact durable results/logs; large artifacts stay in .work")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *suite == "cpp" && strings.HasPrefix(*target, "linux/") {
		explicitImage := false
		flags.Visit(func(f *flag.Flag) { explicitImage = explicitImage || f.Name == "image" })
		if !explicitImage {
			check(*target == "linux/arm64" || *target == "linux/amd64", "Linux C++ cross checks require -image prepared with testdata/toolchains/linux-cross.Dockerfile")
			check(*cxx == "g++", "Linux Clang checks require -image prepared with testdata/toolchains/linux-cpp-clang.Dockerfile")
			if *target == "linux/amd64" {
				*image = cppLinuxAMDImage
			} else {
				*image = cppLinuxArmImage
			}
		}
	}
	check(*suite == "darwin" || *suite == "cpp" || *suite == "tls" || *suite == "linux" || *suite == "linux-cross" || *suite == "gpui" || *suite == "bindings" || *suite == "signatures" || *suite == "bazel" || *suite == "release-smoke" || *suite == "windows" || *suite == "static" || *suite == "all", "unknown suite %q", *suite)
	if *root == "" {
		*root, err = os.Getwd()
		require(err)
	}
	rootInput := *root
	*root, err = filepath.Abs(rootInput)
	if err != nil {
		return fmt.Errorf("resolve source root %q: %w", rootInput, err)
	}
	check(*bao != "", "supply -bao executable, or use bazel run //:verify")
	*bao = resolveRunfile(*bao)
	*goTool = resolveRunfile(*goTool)
	work := filepath.Join(*root, ".work")
	require(os.MkdirAll(work, 0o755))
	scratch := work
	if *suite == "static" && strings.HasPrefix(*target, "linux/") {
		scratch = filepath.Join(work, "static-linux")
		require(os.MkdirAll(scratch, 0755))
	}
	dst, err := os.MkdirTemp(scratch, "verify-"+*suite+"-")
	require(err)
	h := &harness{ctx: ctx, root: *root, work: work, dst: dst, bao: *bao, goTool: *goTool, image: *image, gpui: *gpui, bazel: *bazel, cxx: *cxx, target: *target, env: map[string]string{}, results: map[string]any{}}
	h.windowsCC, h.windowsCXX, h.windowsAR, h.windowsRunner = *windowsCC, *windowsCXX, *windowsAR, *windowsRunner
	h.windowsDriver = *windowsDriver
	h.windowsDLLDir = *windowsDLLDir
	h.staticRuntimeRoot = *staticRuntimeRoot
	h.env = processEnvironment(os.Environ(), runtime.GOOS == "windows")
	h.onlineProxy = h.env["GOPROXY"]
	if h.onlineProxy == "" {
		h.onlineProxy = "https://proxy.golang.org,direct"
	}
	h.onlineSumDB = h.env["GOSUMDB"]
	if h.onlineSumDB == "" {
		h.onlineSumDB = "sum.golang.org"
	}
	delete(h.env, "GOROOT")
	h.env["PATH"] = filepath.Dir(h.goTool) + string(os.PathListSeparator) + h.env["PATH"]
	for key, value := range map[string]string{"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPATH": filepath.Join(work, "go-path"), "GOCACHE": filepath.Join(work, "go-build"), "GOMODCACHE": filepath.Join(work, "go-mod"), "GOPROXY": "off", "GOSUMDB": "off", "CARGO_TARGET_DIR": filepath.Join(dst, "rust-target")} {
		h.env[key] = value
	}
	fmt.Println("Evidence:", dst)
	// Resolve rules_go's runner to the actual SDK executable used for builds and
	// trusted tool hashes. An ordinary explicitly supplied Go executable works too.
	// Its runfiles are in this harness's data tree, not beside the resolved runner.
	goEnv := map[string]string{}
	if h.env["RUNFILES_DIR"] == "" {
		executable, err := os.Executable()
		require(err)
		if info, err := os.Stat(executable + ".runfiles"); err == nil && info.IsDir() {
			goEnv["RUNFILES_DIR"] = executable + ".runfiles"
		}
	}
	goRoot := strings.TrimSpace(string(h.run("go-sdk-root.log", *root, goEnv, h.goTool, "env", "GOROOT")))
	check(filepath.IsAbs(goRoot), "Go SDK root must be absolute; got %q", goRoot)
	goName := "go"
	if runtime.GOOS == "windows" {
		goName = "go.exe"
	}
	h.goTool = resolveRunfile(filepath.Join(goRoot, "bin", goName))
	h.env["PATH"] = filepath.Dir(h.goTool) + string(os.PathListSeparator) + h.env["PATH"]
	goVersion := strings.TrimSpace(string(h.run("go-version.log", *root, nil, h.goTool, "version")))
	check(strings.Contains(goVersion, "go1.26.11 "), "requires Go 1.26.11; got %s", goVersion)
	h.results["go"] = goVersion
	h.results["purego"] = puregoModule + "@" + puregoVersion
	h.results["purego_sum"] = puregoSum
	h.results["dependency_setup"] = "go get pinned module with checksum verification; consumer builds have GOPROXY=off"
	if *suite == "bindings" || *suite == "bazel" || *suite == "release-smoke" || *suite == "static" && strings.HasPrefix(h.target, "darwin/") {
		delete(h.results, "purego")
		delete(h.results, "purego_sum")
		h.results["dependency_setup"] = "none: generated typed consumers use only the standard library; GOPROXY=off"
		h.results["target"] = h.target
	}
	if *suite == "bazel" {
		h.results["dependency_setup"] = "no consumer Go module dependencies; Bazel registry and SDK downloads into isolated build roots"
	}
	switch *suite {
	case "static":
		if strings.HasPrefix(h.target, "linux/") {
			h.linuxStatic()
		} else if strings.HasPrefix(h.target, "windows/") {
			h.windowsStatic()
		} else {
			h.darwinStatic()
		}
	case "windows":
		h.windows()
	case "release-smoke":
		h.releaseSmoke()
	case "darwin":
		h.darwin()
	case "cpp":
		if strings.HasPrefix(h.target, "linux/") {
			h.cppLinux()
		} else {
			h.cpp()
		}
	case "tls":
		h.tls()
	case "linux":
		h.linux()
	case "linux-cross":
		h.linuxCross()
	case "gpui":
		h.gpuiCheck()
	case "signatures":
		h.signatures()
	case "bazel":
		h.bazelConsumer()
	case "bindings":
		if strings.HasPrefix(h.target, "linux/") {
			h.bindingsLinux()
		} else {
			h.bindingsDarwin()
		}
	case "all":
		if runtime.GOOS == "darwin" {
			h.darwin()
			h.tls()
		}
		h.linux()
	}
	if _, ok := h.results["status"]; !ok {
		h.results["status"] = "PASS"
	}
	h.results["cgo_enabled"] = false
	h.results["scope"] = "documented native target profiles; native UI and notarization unverified"
	h.saveJSON("result.json", h.results)
	if *evidence != "" {
		if !filepath.IsAbs(*evidence) {
			*evidence = filepath.Join(h.root, *evidence)
		}
		require(os.Mkdir(*evidence, 0o755))
		entries, err := os.ReadDir(h.dst)
		require(err)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			require(err)
			if info.Size() <= 256<<10 && (filepath.Ext(entry.Name()) == ".json" || filepath.Ext(entry.Name()) == ".log") {
				copyFile(filepath.Join(h.dst, entry.Name()), filepath.Join(*evidence, entry.Name()))
			}
		}
		b, err := json.MarshalIndent(map[string]any{"scratch_directory": h.dst, "bao_sha256": digest(h.bao), "go_executable_sha256": digest(h.goTool)}, "", "  ")
		require(err)
		require(os.WriteFile(filepath.Join(*evidence, "artifacts.json"), append(b, '\n'), 0o644))
	}
	b, err := json.MarshalIndent(h.results, "", "  ")
	require(err)
	fmt.Println(string(b))
	return nil
}

// Windows environment names are case insensitive. Canonicalize before merging
// overrides so Path/PATH cannot randomly discard the VC/Cargo search paths.
func processEnvironment(entries []string, windows bool) map[string]string {
	env := map[string]string{}
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if windows {
			key = strings.ToUpper(key)
		}
		env[key] = value
	}
	return env
}

func resolveRunfile(path string) string {
	path = filepath.FromSlash(path)
	if filepath.VolumeName(path) == "" && filepath.Base(path) == path {
		resolved, err := exec.LookPath(path)
		if err == nil {
			path = resolved
		}
	}
	if _, err := os.Stat(path); err == nil {
		return resolvedToolPath(path)
	}
	executable, err := os.Executable()
	require(err)
	for _, dir := range []string{os.Getenv("RUNFILES_DIR"), executable + ".runfiles"} {
		candidate := filepath.Join(dir, path)
		if dir != "" {
			if _, err := os.Stat(candidate); err == nil {
				return resolvedToolPath(candidate)
			}
		}
	}
	require(fmt.Errorf("cannot locate runfile/tool %q", path))
	return ""
}

func resolvedToolPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		require(fmt.Errorf("resolve tool path %q: %w", path, err))
	}
	// The Windows loader accepts the existing absolute path, including runner
	// junctions. Avoid another filesystem walk just to canonicalize its spelling.
	// Execution and digest() both follow the same path. This is the integration
	// harness; consumer trust-policy checks live in package verify.
	if runtime.GOOS == "windows" {
		return absolute
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		require(fmt.Errorf("resolve tool symlinks %q: %w", absolute, err))
	}
	return resolved
}

func (h *harness) run(log, dir string, extra map[string]string, args ...string) []byte {
	out, err := h.command(log, dir, extra, args...)
	require(err)
	return out
}

func (h *harness) command(log, dir string, extra map[string]string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	env := map[string]string{}
	for k, v := range h.env {
		env[k] = v
	}
	for k, v := range extra {
		env[k] = v
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if log != "" {
		require(os.WriteFile(filepath.Join(h.dst, log), append(append([]byte{}, stdout.Bytes()...), stderr.Bytes()...), 0o644))
	}
	if err != nil {
		return append(append([]byte{}, stdout.Bytes()...), stderr.Bytes()...), fmt.Errorf("%s: %w; log: %s\n%s", strings.Join(args, " "), err, filepath.Join(h.dst, log), stderr.String())
	}
	return stdout.Bytes(), nil
}

func (h *harness) consumer(log, dir string, args ...string) []byte {
	return h.run(log, dir, h.consumerEnv(nil), args...)
}

// consumerEnv disables native compilers with paths interpreted by the host,
// regardless of the target. Go validates CC/CXX even with CGO_ENABLED=0.
func (h *harness) consumerEnv(extra map[string]string) map[string]string {
	root, err := filepath.Abs(filepath.Join(h.dst, "no-native-compilers"))
	require(err)
	env := map[string]string{"CGO_ENABLED": "0"}
	for key, name := range map[string]string{"CC": "cc", "CXX": "cxx", "FC": "fc", "RUSTC": "rustc"} {
		path := filepath.Join(root, name)
		if key != "RUSTC" {
			// cmd/go parses these as quoted argument lists, without unescaping.
			// Preserve backslashes and spaces, including in Windows user paths.
			quote := "\""
			if strings.Contains(path, quote) {
				quote = "'"
				check(!strings.Contains(path, quote), "cannot quote compiler guard path %q", path)
			}
			path = quote + path + quote
		}
		env[key] = path
	}
	for key, value := range extra {
		env[key] = value
	}
	return env
}

func (h *harness) module(dir, name, extra string) {
	require(os.MkdirAll(dir, 0o755))
	text := "module " + name + "\n\ngo 1.26.0\n\nrequire " + puregoModule + " " + puregoVersion + "\n" + extra
	require(os.WriteFile(filepath.Join(dir, "go.mod"), []byte(text), 0o644))
	base := filepath.Base(dir)
	online := map[string]string{"GOPROXY": h.onlineProxy, "GOSUMDB": h.onlineSumDB}
	h.run(base+"-go-get.log", dir, online, h.goTool, "get", puregoModule+"@"+puregoVersion)
	h.run(base+"-go-download.log", dir, online, h.goTool, "mod", "download", "all")
	mod := read(filepath.Join(dir, "go.mod"))
	check(!bytes.Contains(mod, []byte("replace "+puregoModule)), "consumer must not replace purego with a local checkout")
	sums := read(filepath.Join(dir, "go.sum"))
	check(bytes.Contains(sums, []byte(puregoModule+" "+puregoVersion+" "+puregoSum+"\n")), "purego module checksum does not match the pinned version")
}

func (h *harness) saveJSON(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	require(err)
	require(os.WriteFile(filepath.Join(h.dst, name), append(b, '\n'), 0o644))
}
func read(path string) []byte { b, err := os.ReadFile(path); require(err); return b }
func copyFile(src, dst string) {
	require(os.MkdirAll(filepath.Dir(dst), 0o755))
	require(os.WriteFile(dst, read(src), 0o644))
}
func digest(path string) string { return fmt.Sprintf("%x", sha256.Sum256(read(path))) }
func readJSON(path string) map[string]any {
	var v map[string]any
	require(json.Unmarshal(read(path), &v))
	return v
}
func copyTree(src, dst string) {
	require(filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		return os.WriteFile(out, read(path), 0o644)
	}))
}
