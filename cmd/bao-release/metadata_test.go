package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseTagMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release metadata runs on Unix hosts")
	}
	script, err := filepath.Abs("../../release/metadata.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	env := append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Release fixture", "GIT_AUTHOR_EMAIL=release@example.invalid",
		"GIT_COMMITTER_NAME=Release fixture", "GIT_COMMITTER_EMAIL=release@example.invalid",
	)
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = repo, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture")
	commit := git("rev-parse", "HEAD")
	epoch := git("show", "-s", "--format=%ct", "HEAD")
	for _, tc := range []struct {
		tag, prerelease string
		annotated       bool
	}{
		{"v0.0.0", "true", false},
		{"v0.1.0", "false", false},
		{"v0.1.0-rc.1", "true", true},
		{"v0.1.0+build.1", "false", false},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if tc.annotated {
				git("-c", "tag.gpgsign=false", "tag", "-am", "fixture", tc.tag)
			} else {
				git("-c", "tag.gpgsign=false", "tag", tc.tag)
			}
			cmd := exec.Command("bash", script, tc.tag)
			cmd.Dir, cmd.Env = repo, env
			out, err := cmd.CombinedOutput()
			want := "tag=" + tc.tag + "\ncommit=" + commit + "\nepoch=" + epoch + "\nprerelease=" + tc.prerelease + "\n"
			if err != nil || string(out) != want {
				t.Fatalf("metadata: %v\n%s\nwant:\n%s", err, out, want)
			}
		})
	}
	for _, tag := range []string{"v01.0.0", "v0.1.0-01", "../v0.0.0", "v0.0.0\ncommit=bad"} {
		cmd := exec.Command("bash", script, tag)
		cmd.Dir, cmd.Env = repo, env
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("accepted invalid tag %q: %s", tag, out)
		}
	}
	git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "different checkout")
	cmd := exec.Command("bash", script, "v0.0.0")
	cmd.Dir, cmd.Env = repo, env
	if out, err := cmd.CombinedOutput(); err == nil || !bytes.Contains(out, []byte("Checkout does not match release tag")) {
		t.Fatalf("accepted mismatched tag/checkout: %v\n%s", err, out)
	}
}
