package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIResultContentAddress(t *testing.T) {
	script, err := filepath.Abs("../../ci/cache.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo, results := t.TempDir(), t.TempDir()
	env := append(os.Environ(), "BAO_CI_ROOT="+repo, "BAO_CI_RESULT_DIR="+results,
		"ImageOS=fixture-os", "ImageVersion=fixture-1", "RUNNER_OS=Linux", "RUNNER_ARCH=ARM64",
		"GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=fixture/bao", "GITHUB_RUN_ID=123",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = repo, env
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, b)
		}
	}
	run := func(ok bool, args ...string) string {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if (err == nil) != ok {
			t.Fatalf("cache %v: %v: %s", args, err, b)
		}
		return string(b)
	}
	key := func(suite string) string {
		t.Helper()
		b := run(true, "fingerprint", suite)
		if !strings.Contains(b, "cacheable=true\n") {
			t.Fatalf("missing runner identity: %s", b)
		}
		return strings.TrimPrefix(strings.Split(b, "\n")[0], "key=")
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "source"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "first")
	original := key("unit")
	run(false, "validate", "unit", original) // No marker means no cached pass.
	run(true, "record", "unit", original)
	if b := run(true, "validate", "unit", original); !strings.Contains(b, "/runs/123") {
		t.Fatalf("lost original evidence: %s", b)
	}
	git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "same tree, different commit")
	if key("unit") != original {
		t.Fatal("commit metadata changed content identity")
	}
	run(true, "validate", "unit", original)
	if key("darwin-arm64") == original {
		t.Fatal("suite missing from key")
	}
	if key("linux-amd64") == key("linux-arm64") {
		t.Fatal("Linux architecture missing from result identity")
	}
	env = append(env, "ImageVersion=fixture-2")
	if key("unit") == original {
		t.Fatal("runner image missing from key")
	}
	run(false, "validate", "unit", original)
	env = append(env, "ImageVersion=fixture-1")
	marker := filepath.Join(results, "result.txt")
	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []string{strings.Replace(string(b), "passed", "failed", 1), string(b) + "extra\n", strings.Replace(string(b), "fixture/bao", "attacker/bao", 1), "partial\n"} {
		if err := os.WriteFile(marker, []byte(corrupt), 0600); err != nil {
			t.Fatal(err)
		}
		run(false, "validate", "unit", original)
	}
	if err := os.WriteFile(filepath.Join(repo, "source"), []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	run(false, "fingerprint", "unit") // A dirty checkout cannot claim its HEAD's content.
	run(false, "record", "unit", original)
	git("add", "source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "changed source")
	if key("unit") == original {
		t.Fatal("source change did not invalidate cached pass")
	}
	run(false, "record", "unit", original)
	env = append(env, "ImageVersion=")
	if b := run(true, "fingerprint", "unit"); !strings.Contains(b, "cacheable=false") {
		t.Fatalf("unknown runner was cacheable: %s", b)
	}
}

func TestReleaseWaitsForSourceCIWithoutTreatingItAsACacheHit(t *testing.T) {
	script, err := filepath.Abs("../../ci/await-source.sh")
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	result := func(status, conclusion string) string {
		return sha + "\tmain\t" + status + "\t" + conclusion + "\t123\thttps://github.com/fixture/bao/actions/runs/123\n"
	}
	for _, tc := range []struct {
		name, responses string
		ok              bool
	}{
		{"completed", result("completed", "success"), true},
		{"wait", result("in_progress", "pending") + result("completed", "success"), true},
		{"creation-race", "missing\n" + result("in_progress", "pending") + result("completed", "success"), true},
		{"no-source-run-fallback", "missing\nmissing\nmissing\n", true},
		{"failure", result("completed", "failure"), false},
		{"cancelled", result("completed", "cancelled"), false},
		{"timeout", strings.Repeat(result("in_progress", "pending"), 4), false},
		{"foreign-commit", strings.Replace(result("completed", "success"), sha, strings.Repeat("b", 40), 1), false},
		{"foreign-branch", strings.Replace(result("completed", "success"), "\tmain\t", "\tfeature\t", 1), false},
		{"foreign-url", strings.Replace(result("completed", "success"), "fixture/bao/actions", "foreign/bao/actions", 1), false},
		{"unknown-state", result("unexpected", "pending"), false},
		{"api-error", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fixture, counter, args := filepath.Join(dir, "responses"), filepath.Join(dir, "count"), filepath.Join(dir, "args")
			if err := os.WriteFile(fixture, []byte(tc.responses), 0600); err != nil {
				t.Fatal(err)
			}
			fake := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$@" >> "$BAO_WAIT_ARGS"
n=0
if [[ -f $BAO_WAIT_COUNT ]]; then read -r n < "$BAO_WAIT_COUNT"; fi
n=$((n+1))
echo "$n" > "$BAO_WAIT_COUNT"
line=$(sed -n "${n}p" "$BAO_WAIT_RESPONSES")
[[ -n $line ]] || exit 1
printf '%s\n' "$line"
`
			if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script, sha, "main")
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GITHUB_REPOSITORY=fixture/bao", "GITHUB_SERVER_URL=https://github.com",
				"BAO_WAIT_RESPONSES="+fixture, "BAO_WAIT_COUNT="+counter, "BAO_WAIT_ARGS="+args,
				"BAO_CI_WAIT_ATTEMPTS=4", "BAO_CI_WAIT_INTERVAL=0")
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("wait: %v: %s", err, out)
			}
			request, err := os.ReadFile(args)
			if err != nil {
				t.Fatal(err)
			}
			for _, arg := range []string{"repos/fixture/bao/actions/workflows/ci.yml/runs", "head_sha=" + sha, "branch=main", "event=push"} {
				if !strings.Contains(string(request), arg+"\n") {
					t.Fatalf("missing constrained API argument %s", arg)
				}
			}
			if tc.name == "completed" && !strings.Contains(string(out), "validate the content-addressed results") {
				t.Fatal("source run incorrectly substituted for exact cache validation")
			}
		})
	}
}
