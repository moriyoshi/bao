package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ScanOptions selects an offline scan of the current module's dependency list.
// Policy and Envelopes may be omitted only when no downloaded native inputs exist.
type ScanOptions struct {
	Directory, Go, Target string
	Policy                Policy
	Envelopes             []Envelope
	Stderr                io.Writer
}

// ModuleScan reports a dependency's downloaded source tree, not compiled archives.
type ModuleScan struct {
	Path        string   `json:"module"`
	Version     string   `json:"version,omitempty"`
	Directory   string   `json:"directory,omitempty"`
	Replacement bool     `json:"local_replacement,omitempty"`
	Status      string   `json:"status"`
	NativeFiles []string `json:"native_files,omitempty"`
}

// ScanReport describes source checks only. It does not attest to a later build,
// a shared build cache, or the actual archives selected by a linker.
type ScanReport struct {
	Target        string       `json:"target"`
	MainModule    string       `json:"main_module"`
	Modules       []ModuleScan `json:"dependencies"`
	NativeFiles   int          `json:"native_files"`
	Authenticated []string     `json:"authenticated_modules"`
	Integrity     string       `json:"module_cache_integrity"`
	Scope         string       `json:"scope"`
}

// Scan checks already-downloaded dependency modules without compiling, linking,
// downloading or executing consumer code. It runs the trusted Go resolver and
// go mod verify offline, then checks complete signed native module trees.
// The main consumer module is outside this dependency-only scan. Local
// replacements are scanned as dependencies but are not covered by go mod verify.
// Dependencies whose sources have not been downloaded are reported explicitly.
// A native dependency without a matching independently approved manifest fails.
func Scan(ctx context.Context, o ScanOptions) (ScanReport, error) {
	report := ScanReport{Target: o.Target, Scope: "downloaded dependency source trees only; no build-cache or linker-input enforcement", Modules: []ModuleScan{}, Authenticated: []string{}}
	parts := strings.Split(o.Target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return report, fmt.Errorf("invalid target")
	}
	approved := map[string]Manifest{}
	if o.Policy.Schema != 0 || len(o.Policy.Keys) != 0 || len(o.Policy.Approvals) != 0 || len(o.Envelopes) != 0 {
		var err error
		approved, err = Authenticate(o.Policy, o.Envelopes, o.Target)
		if err != nil {
			return report, err
		}
	}
	goTool, err := exec.LookPath(o.Go)
	if err != nil {
		return report, err
	}
	goTool, err = filepath.Abs(goTool)
	if err != nil {
		return report, err
	}
	work, err := os.MkdirTemp("", "bao-scan-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, goTool, args...)
		cmd.Dir, cmd.Env, cmd.Stderr = o.Directory, buildEnv(parts[0], parts[1], work), o.Stderr
		b, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("offline go %s: %w", strings.Join(args, " "), err)
		}
		return b, nil
	}
	b, err := run("env", "GOVERSION")
	if err != nil {
		return report, err
	}
	if strings.TrimSpace(string(b)) != "go1.26.10" {
		return report, fmt.Errorf("verification profile requires stock Go 1.26.10, got %s", strings.TrimSpace(string(b)))
	}
	b, err = run("list", "-m", "-mod=readonly", "-json", "all")
	if err != nil {
		return report, err
	}
	var modules []scanModule
	d := json.NewDecoder(strings.NewReader(string(b)))
	for {
		var m scanModule
		if err := d.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return report, err
		}
		modules = append(modules, m)
	}
	if _, err = run("mod", "verify"); err != nil {
		return report, err
	}
	report.Integrity = "go mod verify passed; local replacements excluded from Go's cache integrity check"
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	seen := map[string]bool{}
	var failures []string
	for _, m := range modules {
		if m.Main {
			report.MainModule = m.Path
			continue
		}
		dir := m.Dir
		if m.Replace != nil {
			dir = m.Replace.Dir
		}
		entry := ModuleScan{Path: m.Path, Version: m.Version, Directory: dir, Replacement: m.Replace != nil && m.Replace.Version == "", Status: "not-downloaded"}
		if dir == "" {
			report.Modules = append(report.Modules, entry)
			continue
		}
		files, err := Tree(dir, "")
		if err != nil {
			return report, fmt.Errorf("%s: %w", m.Path, err)
		}
		for _, f := range files {
			if filepath.Ext(f.Path) == ".syso" {
				entry.NativeFiles = append(entry.NativeFiles, f.Path)
				report.NativeFiles++
			}
		}
		entry.Status = "unsigned-no-native-inputs"
		if manifest, ok := approved[m.Path]; ok {
			seen[m.Path] = true
			if err := MatchTree(manifest, files); err != nil {
				entry.Status = "rejected"
				failures = append(failures, fmt.Sprintf("%s: %v", m.Path, err))
			} else {
				entry.Status = "authenticated"
				report.Authenticated = append(report.Authenticated, m.Path)
			}
		} else if len(entry.NativeFiles) != 0 {
			entry.Status = "unapproved-native-inputs"
			failures = append(failures, fmt.Sprintf("native dependency %s requires an independently approved policy and signed manifest", m.Path))
		}
		report.Modules = append(report.Modules, entry)
	}
	if report.MainModule == "" {
		return report, fmt.Errorf("scan requires a consumer Go module; workspaces are disabled")
	}
	for module := range approved {
		if !seen[module] {
			failures = append(failures, fmt.Sprintf("approved module %s is absent or not downloaded", module))
		}
	}
	if len(failures) != 0 {
		sort.Strings(failures)
		return report, fmt.Errorf("source verification failed: %s", strings.Join(failures, "; "))
	}
	return report, nil
}

type scanModule struct {
	Path, Version, Dir string
	Main               bool
	Replace            *scanModule
}
