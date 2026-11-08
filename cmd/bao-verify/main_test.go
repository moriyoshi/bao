package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConsumerCompilerGuards(t *testing.T) {
	h := &harness{dst: filepath.Join(t.TempDir(), "paths with spaces")}
	env := h.consumerEnv(map[string]string{"GOOS": "windows", "GOARCH": "arm64"})
	if env["CGO_ENABLED"] != "0" || env["GOOS"] != "windows" || env["GOARCH"] != "arm64" {
		t.Fatalf("lost consumer target/environment: %#v", env)
	}
	for _, key := range []string{"CC", "CXX", "FC", "RUSTC"} {
		path := env[key]
		if key != "RUSTC" {
			if len(path) < 2 || path[0] != path[len(path)-1] || (path[0] != '\'' && path[0] != '"') {
				t.Fatalf("%s is not quoted for Go's compiler argument parser: %q", key, path)
			}
			path = path[1 : len(path)-1]
		}
		if !filepath.IsAbs(path) {
			t.Fatalf("%s is not absolute on the host: %q", key, path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s guard should be unavailable: %s %v", key, path, err)
		}
	}
}

func TestConsumerBuildWithGo(t *testing.T) {
	goTool := os.Getenv("BAO_VERIFY_TEST_GO")
	if goTool != "" {
		goTool = resolveRunfile(goTool)
	} else {
		var err error
		goTool, err = exec.LookPath("go")
		if err != nil {
			t.Skip("Go executable is not on PATH; native CI supplies its pinned SDK")
		}
	}
	// Bazel supplies neither a user home nor a Go cache by default. Exercise
	// that environment even when a developer's shell provides all four.
	for _, key := range []string{"HOME", "XDG_CACHE_HOME", "GOCACHE", "GOPATH"} {
		t.Setenv(key, "")
	}
	dir := filepath.Join(t.TempDir(), "consumer with spaces")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module consumer-check\ngo 1.26.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h := &harness{ctx: context.Background(), dst: dir, env: processEnvironment(os.Environ(), runtime.GOOS == "windows")}
	delete(h.env, "GOROOT")
	for k, v := range map[string]string{"GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off"} {
		h.env[k] = v
	}
	for _, key := range []string{"GOCACHE", "GOPATH"} {
		if !filepath.IsAbs(h.env[key]) {
			h.env[key] = filepath.Join(dir, key)
		}
	}
	exe := filepath.Join(dir, "consumer.exe")
	// Exercise the host Go executable, rather than only cross-compiling a
	// Windows consumer with Unix Go (which accepts /bao-no-cc).
	extra := h.consumerEnv(map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH})
	if out, err := h.command("build.log", dir, extra, goTool, "build", "-o", exe, "."); err != nil {
		t.Fatalf("consumer rejected disabled compiler paths: %v\n%s", err, out)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatal(err)
	}
	// Negative control: enabling CGO must still fail with these unavailable
	// compilers. Removing guards to bypass validation would weaken this check.
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nimport \"C\"\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	extra["CGO_ENABLED"] = "1"
	if out, err := h.command("cgo-negative.log", dir, extra, goTool, "build", "-o", exe, "."); err == nil || !strings.Contains(string(out), "no-native-compilers") {
		t.Fatalf("CGO did not fail on the compiler guard: %v\n%s", err, out)
	}
}

func TestWindowsEnvironmentPreservesCompilerPath(t *testing.T) {
	env := processEnvironment([]string{"Path=C:\\VC;C:\\Cargo", "GoRoot=C:\\old-go", "SystemRoot=C:\\Windows", "=C:=C:\\work"}, true)
	env["PATH"] = "C:\\Go;" + env["PATH"]
	delete(env, "GOROOT")
	if env["PATH"] != "C:\\Go;C:\\VC;C:\\Cargo" || env["SYSTEMROOT"] != "C:\\Windows" || len(env) != 2 {
		t.Fatalf("Windows compiler environment lost or duplicated: %#v", env)
	}
	unix := processEnvironment([]string{"Path=case-sensitive", "PATH=/bin"}, false)
	if len(unix) != 2 || unix["Path"] != "case-sensitive" || unix["PATH"] != "/bin" {
		t.Fatal("Unix case sensitivity lost")
	}
}

func TestResolveRunfileToolPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tools with spaces")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	name := "bao-path-probe"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	tool := filepath.Join(dir, name)
	if err := os.WriteFile(tool, []byte("tool identity"), 0755); err != nil {
		t.Fatal(err)
	}
	assertTool := func(input string) {
		t.Helper()
		resolved := resolveRunfile(input)
		if !filepath.IsAbs(resolved) {
			t.Fatalf("non-absolute tool: %s", resolved)
		}
		want, err := os.Stat(tool)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.Stat(resolved)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(want, got) {
			t.Fatalf("resolved another tool: %s", resolved)
		}
	}
	t.Run("absolute", func(t *testing.T) { assertTool(tool) })
	t.Run("forward slashes", func(t *testing.T) { assertTool(filepath.ToSlash(tool)) })
	t.Run("PATH", func(t *testing.T) {
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		assertTool(name)
	})
	t.Run("symlink", func(t *testing.T) {
		alias := filepath.Join(dir, "alias-"+name)
		if err := os.Symlink(tool, alias); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		assertTool(alias)
	})
	t.Run("runfiles", func(t *testing.T) {
		runfiles := filepath.Join(t.TempDir(), "runfiles with spaces")
		logical := filepath.Join("workspace", name)
		path := filepath.Join(runfiles, logical)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("runfile identity"), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("RUNFILES_DIR", runfiles)
		resolved := resolveRunfile(filepath.ToSlash(logical))
		b, err := os.ReadFile(resolved)
		if err != nil || string(b) != "runfile identity" || !filepath.IsAbs(resolved) {
			t.Fatalf("runfile resolution: %s %v", resolved, err)
		}
	})
}
