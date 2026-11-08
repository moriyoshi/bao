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
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
)

type LinkReport struct {
	Archives      map[string]string `json:"archive_sha256"`
	NativeMembers int               `json:"native_members"`
}

// CheckArchive verifies all members, not source paths. Unknown payloads, missing
// native bytes and duplicate/substituted members fail before linker execution.
func CheckArchive(data []byte, expected PackageInputs) (int, error) {
	members, err := ar.Parse(data)
	if err != nil {
		return 0, err
	}
	want := map[string]map[string]int{}
	for name, hashes := range expected.Native {
		want[name] = map[string]int{}
		for _, h := range hashes {
			want[name][h]++
		}
	}
	seen := map[string]int{}
	native := 0
	pkgdef := 0
	for _, m := range members {
		h := Digest(m.Data)
		if want[m.Name][h] > 0 {
			want[m.Name][h]--
			native++
			continue
		}
		if m.Name == "__.PKGDEF" {
			pkgdef++
			if pkgdef > 1 {
				return 0, fmt.Errorf("duplicate package definition")
			}
			continue
		}
		if expected.GoMembers[m.Name] <= seen[m.Name] || !bytes.HasPrefix(m.Data, []byte("go object ")) {
			return 0, fmt.Errorf("unexpected or substituted archive member %q", m.Name)
		}
		seen[m.Name]++
	}
	if pkgdef != 1 || seen["_go_.o"] != 1 {
		return 0, fmt.Errorf("incomplete Go package archive")
	}
	for name, n := range expected.GoMembers {
		if seen[name] != n {
			return 0, fmt.Errorf("missing Go assembly member %q", name)
		}
	}
	for name, hashes := range want {
		for _, n := range hashes {
			if n != 0 {
				return 0, fmt.Errorf("missing signed native member %q", name)
			}
		}
	}
	return native, nil
}

// Tool implements the subprocess hook used by Bao's verified-build command.
// It requires Build's private configuration and is not a standalone verification
// entrypoint. A link-only -toolexec hook cannot enforce checks on warm-cache builds.
func Tool(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing Go tool")
	}
	b, err := os.ReadFile(os.Getenv("BAO_VERIFY_CONFIG"))
	if err != nil {
		return fmt.Errorf("requires verified-build private configuration: %w", err)
	}
	var config HookConfig
	if err = Decode(b, &config); err != nil {
		return err
	}
	if config.Schema != 1 || filepath.Dir(args[0]) != config.ToolDirectory {
		return fmt.Errorf("unexpected Go tool path")
	}
	tool := filepath.Base(args[0])
	if tool != "compile" && tool != "asm" && tool != "link" {
		return fmt.Errorf("unsupported Go tool %q", tool)
	}
	if tool == "link" && !(len(args) == 2 && args[1] == "-V=full") {
		args, err = bindLink(args, config)
		if err != nil {
			return err
		}
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func bindLink(args []string, c HookConfig) ([]string, error) {
	args = append([]string(nil), args...)
	idx := -1
	for i := 1; i < len(args); i++ {
		if args[i] == "-importcfg" {
			if idx >= 0 || i+1 == len(args) {
				return nil, fmt.Errorf("invalid linker importcfg")
			}
			idx = i + 1
		}
	}
	if idx < 0 || len(args) < 2 {
		return nil, fmt.Errorf("missing linker importcfg")
	}
	b, err := os.ReadFile(args[idx])
	if err != nil {
		return nil, err
	}
	sealed, err := os.MkdirTemp(c.Private, "link-inputs-")
	if err != nil {
		return nil, err
	}
	report := LinkReport{Archives: map[string]string{}}
	paths := map[string]string{}
	copyArchive := func(pkg, source string) (string, error) {
		expected, ok := c.Packages[pkg]
		if !ok {
			return "", fmt.Errorf("linker input package %s was not resolved from snapshots", pkg)
		}
		// Read once, verify those bytes, publish a new private read-only copy, and
		// give its path to the linker. Do not validate one path then use another.
		data, err := os.ReadFile(source)
		if err != nil {
			return "", err
		}
		n, err := CheckArchive(data, expected)
		if err != nil {
			return "", fmt.Errorf("archive %s: %w", pkg, err)
		}
		h := Digest(data)
		if previous, duplicate := report.Archives[pkg]; duplicate {
			// cmd/go also lists main in importcfg. The positional main archive
			// must agree byte-for-byte with that packagefile entry.
			if previous != h {
				return "", fmt.Errorf("inconsistent duplicate package archive %s", pkg)
			}
			return paths[pkg], nil
		}
		report.Archives[pkg] = h
		report.NativeMembers += n
		p := filepath.Join(sealed, fmt.Sprintf("%04d.a", len(report.Archives)))
		if err = WriteNew(p, data, 0400); err != nil {
			return "", err
		}
		paths[pkg] = p
		return p, nil
	}
	lines := strings.Split(string(b), "\n")
	listed := map[string]bool{}
	for i, line := range lines {
		if strings.HasPrefix(line, "packagefile ") {
			pkg, p, ok := strings.Cut(strings.TrimPrefix(line, "packagefile "), "=")
			if !ok || pkg == "" || p == "" {
				return nil, fmt.Errorf("invalid packagefile")
			}
			if listed[pkg] {
				return nil, fmt.Errorf("duplicate packagefile %s", pkg)
			}
			listed[pkg] = true
			dst, err := copyArchive(pkg, p)
			if err != nil {
				return nil, err
			}
			lines[i] = "packagefile " + pkg + "=" + dst
		} else if line != "" && !strings.HasPrefix(line, "packageshlib ") && !strings.HasPrefix(line, "modinfo ") {
			return nil, fmt.Errorf("unsupported linker importcfg entry %q", line)
		} else if strings.HasPrefix(line, "packageshlib ") {
			return nil, fmt.Errorf("shared-library inputs are unsupported")
		}
	}
	main, err := copyArchive(c.Main, args[len(args)-1])
	if err != nil {
		return nil, err
	}
	args[len(args)-1] = main
	cfg := filepath.Join(sealed, "importcfg")
	if err = WriteNew(cfg, []byte(strings.Join(lines, "\n")), 0400); err != nil {
		return nil, err
	}
	args[idx] = cfg
	if err = os.Chmod(sealed, 0500); err != nil {
		return nil, err
	}
	// A fresh outer cache makes this callback mandatory; the outer command also
	// requires this report before publishing an executable.
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if err = WriteNew(filepath.Join(c.Private, "link-report.json"), encoded, 0400); err != nil {
		return nil, err
	}
	return args, nil
}
