package toolchain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Command struct {
	Tool string   `json:"tool"`
	Args []string `json:"args"`
	Dir  string   `json:"directory,omitempty"`
}

type RunFunc func(context.Context, Command) ([]byte, error)

// Executor uses argv directly, never a shell. Its command log records successful
// tool execution paths, so generated packages retain their producer provenance.
type Executor struct {
	Stderr   io.Writer
	Commands []Command
}

func (e *Executor) Run(ctx context.Context, c Command) ([]byte, error) {
	path, err := exec.LookPath(c.Tool)
	if err != nil {
		return nil, fmt.Errorf("required producer tool %q is unavailable: %w", c.Tool, err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.Tool = path
	e.Commands = append(e.Commands, c)
	command := exec.CommandContext(ctx, path, c.Args...)
	command.Dir = c.Dir
	command.Stderr = e.Stderr
	output, err := command.Output()
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	if err != nil {
		return output, fmt.Errorf("%s failed: %w", filepath.Base(path), err)
	}
	return output, nil
}

func DefaultLinker(target Target) string {
	if strings.HasPrefix(target.Name, "windows/") {
		return ""
	} // COFF archives are selected directly.
	if strings.HasPrefix(target.Name, "darwin/") {
		if runtime.GOOS == "darwin" {
			return "/usr/bin/ld"
		}
		return ""
	}
	if target.Name == runtime.GOOS+"/"+runtime.GOARCH {
		return "ld"
	}
	switch target.Name {
	case "linux/amd64":
		return "x86_64-linux-gnu-ld"
	case "linux/loong64":
		return "loongarch64-linux-gnu-ld"
	case "linux/ppc64le":
		return "powerpc64le-linux-gnu-ld"
	default:
		return "aarch64-linux-gnu-ld"
	}
}

// SDKVersion reads the version belonging to the supplied SDK, including an SDK
// different from xcrun's default. No host SDK version is guessed for cross use.
func SDKVersion(sdk string) (string, error) {
	b, err := os.ReadFile(filepath.Join(sdk, "SDKSettings.json"))
	if err != nil {
		return "", fmt.Errorf("read SDKSettings.json: %w", err)
	}
	var settings struct{ Version string }
	if err := json.Unmarshal(b, &settings); err != nil {
		return "", err
	}
	if !numericVersion(settings.Version) {
		return "", fmt.Errorf("SDK has no valid numeric Version")
	}
	return settings.Version, nil
}

func numericVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func Combine(ctx context.Context, run RunFunc, target Target, linker, sdk, minOS, archive, output string) error {
	return CombineWithArchives(ctx, run, target, linker, sdk, minOS, archive, output, nil)
}

// CombineWithArchives retains the primary input and resolves its undefined
// references from additional static archives. Dependency archives are searched,
// rather than whole-loaded, to avoid importing unrelated runtime startup code.
// Windows selection remains inside Bao and never invokes a native linker.
func CombineWithArchives(ctx context.Context, run RunFunc, target Target, linker, sdk, minOS, archive, output string, dependencies []string) error {
	if strings.HasPrefix(target.Name, "windows/") {
		return combineCOFFArchives(target, archive, output, dependencies)
	}
	for _, path := range dependencies {
		t, isArchive, err := Detect(path)
		if err != nil {
			return fmt.Errorf("dependency archive %s: %w", path, err)
		}
		if !isArchive || t.Name != target.Name {
			return fmt.Errorf("dependency %s must be a static archive for %s", path, target.Name)
		}
	}
	if linker == "" {
		linker = DefaultLinker(target)
	}
	if linker == "" {
		return fmt.Errorf("Darwin archive combination requires a compatible Apple partial linker; combine on macOS or supply -ld")
	}
	// Absolute paths cannot become linker options even if a filename starts '-'.
	input, err := filepath.Abs(archive)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	var args []string
	if strings.HasPrefix(target.Name, "darwin/") {
		if !numericVersion(minOS) {
			return fmt.Errorf("invalid macOS deployment version %q", minOS)
		}
		version, err := SDKVersion(sdk)
		if err != nil {
			return err
		}
		arch := "arm64"
		if target.Name == "darwin/amd64" {
			arch = "x86_64"
		}
		args = []string{"-r", "-arch", arch, "-platform_version", "macos", minOS, version}
		if len(dependencies) == 0 {
			args = append(args, "-all_load", input)
		} else {
			_, isArchive, err := Detect(input)
			if err != nil {
				return err
			}
			if isArchive {
				args = append(args, "-force_load", input)
			} else {
				args = append(args, input)
			}
			for _, path := range dependencies {
				absolute, err := filepath.Abs(path)
				if err != nil {
					return err
				}
				args = append(args, absolute)
			}
		}
		args = append(args, "-o", output)
	} else {
		args = []string{"-r", "--whole-archive", input, "--no-whole-archive"}
		if len(dependencies) > 0 {
			args = append(args, "--start-group")
			for _, path := range dependencies {
				absolute, err := filepath.Abs(path)
				if err != nil {
					return err
				}
				args = append(args, absolute)
			}
			args = append(args, "--end-group")
		}
		args = append(args, "-o", output)
	}
	_, err = run(ctx, Command{Tool: linker, Args: args})
	return err
}

type CargoOptions struct {
	Manifest string
	Package  string
	Target   Target
	Offline  bool
	Locked   bool
	Debug    bool
}

// CargoArchive selects a staticlib using Cargo's metadata and actual artifact
// messages, including configured output directories. It never guesses a target
// directory or chooses an unrelated dependency's archive.
func CargoArchive(ctx context.Context, run RunFunc, opts CargoOptions, diagnostics io.Writer) (string, error) {
	manifest, err := filepath.Abs(opts.Manifest)
	if err != nil {
		return "", err
	}
	manifest, err = filepath.EvalSymlinks(manifest)
	if err != nil {
		return "", err
	}
	flags := []string{"--manifest-path", manifest}
	if opts.Offline {
		flags = append(flags, "--offline")
	}
	if opts.Locked {
		flags = append(flags, "--locked")
	}
	if opts.Debug {
		flags = append(flags, "--config", "profile.release.debug=2", "--config", `profile.release.strip="none"`)
	}
	metadata, err := run(ctx, Command{Tool: "cargo", Dir: filepath.Dir(manifest), Args: append([]string{"metadata", "--format-version", "1", "--no-deps"}, flags...)})
	if err != nil {
		return "", err
	}
	var m struct {
		WorkspaceMembers []string `json:"workspace_members"`
		Packages         []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			ManifestPath string `json:"manifest_path"`
			Targets      []struct {
				Name       string   `json:"name"`
				CrateTypes []string `json:"crate_types"`
			} `json:"targets"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return "", fmt.Errorf("decode cargo metadata: %w", err)
	}
	members := make(map[string]bool)
	for _, id := range m.WorkspaceMembers {
		members[id] = true
	}
	type candidate struct{ id, name, target string }
	var choices []candidate
	memberManifest := false
	for _, p := range m.Packages {
		memberManifest = memberManifest || filepath.Clean(p.ManifestPath) == manifest
	}
	for _, p := range m.Packages {
		if !members[p.ID] {
			continue
		}
		if opts.Package != "" && opts.Package != p.Name {
			continue
		}
		// An explicit member manifest selects that package; a workspace manifest
		// requires an unambiguous staticlib or -cargo-package.
		if opts.Package == "" && memberManifest && filepath.Clean(p.ManifestPath) != manifest {
			continue
		}
		for _, t := range p.Targets {
			if contains(t.CrateTypes, "staticlib") {
				choices = append(choices, candidate{p.ID, p.Name, t.Name})
			}
		}
	}
	if len(choices) != 1 {
		return "", fmt.Errorf("Cargo manifest selects %d staticlib targets; declare crate-type = [\"staticlib\"] and select one package with -cargo-package", len(choices))
	}
	selected := choices[0]
	args := append([]string{"build", "--release", "--lib", "--package", selected.name, "--target", opts.Target.RustTriple, "--message-format=json-render-diagnostics"}, flags...)
	output, buildErr := run(ctx, Command{Tool: "cargo", Dir: filepath.Dir(manifest), Args: args})
	var archives []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		var message struct {
			Reason    string                    `json:"reason"`
			PackageID string                    `json:"package_id"`
			Filenames []string                  `json:"filenames"`
			Target    struct{ Name string }     `json:"target"`
			Message   struct{ Rendered string } `json:"message"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			if buildErr != nil {
				return "", buildErr
			}
			return "", fmt.Errorf("decode Cargo build output: %w", err)
		}
		if message.Reason == "compiler-message" {
			fmt.Fprint(diagnostics, message.Message.Rendered)
		}
		if message.Reason == "compiler-artifact" && message.PackageID == selected.id && message.Target.Name == selected.target {
			for _, filename := range message.Filenames {
				if filepath.Ext(filename) == ".a" && !contains(archives, filename) {
					archives = append(archives, filename)
				}
			}
		}
	}
	if buildErr != nil {
		return "", buildErr
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(archives) != 1 {
		return "", fmt.Errorf("Cargo did not report exactly one archive for %s", selected.name)
	}
	if !filepath.IsAbs(archives[0]) {
		archives[0] = filepath.Join(filepath.Dir(manifest), archives[0])
	}
	return archives[0], nil
}

func contains(values []string, value string) bool {
	for _, s := range values {
		if s == value {
			return true
		}
	}
	return false
}
