package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAndVersionAreSuccessfulAndDoNotUseStderr(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"help", "build"}, {"translate", "--help"}, {"translate-elf", "--help"}, {"doctor", "--help"}, {"inspect", "--help"}, {"pack", "--help"}, {"verify", "--help"}, {"verified-build", "--help"}, {"sign", "--help"}, {"keygen", "--help"}, {"version"}, {"version", "--json"}, {"targets", "--json"}} {
		var out, errout strings.Builder
		if err := run(args, &out, &errout); err != nil || out.Len() == 0 || errout.Len() != 0 {
			t.Fatalf("args=%v err=%v stdout=%s stderr=%s", args, err, out.String(), errout.String())
		}
	}
}

func TestUsageErrorsHaveExitCodeTwo(t *testing.T) {
	for _, args := range [][]string{{"not-a-command"}, {"help", "build", "extra"}, {"build", "--unknown"}, {"build", "-o", "x", "-target", "linux/riscv64"}, {"translate", "-o", "x"}, {"verified-build"}, {"sign"}, {"keygen"}, {"version", "unexpected"}, {"targets", "unexpected"}} {
		var out, errout strings.Builder
		err := run(args, &out, &errout)
		if err == nil || exitCode(err) != 2 || out.Len() != 0 || errout.Len() != 0 {
			t.Fatalf("args=%v error=%v code=%d output=%s %s", args, err, exitCode(err), out.String(), errout.String())
		}
	}
	if exitCode(context.Canceled) != 130 {
		t.Fatal("interrupt status lost")
	}
}

func TestVerificationUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"verify", "./..."}, {"verify", "-policy", "unused"}, {"verify", "-manifest", "unused"},
		{"verified-build", "-policy", "unused", "-manifest", "unused", "-o", "unused", "-backend", "other"},
		{"verified-build", "-policy", "unused", "-manifest", "unused", "-o", "unused", "-backend", "bazel"},
		{"verified-build", "-policy", "unused", "-manifest", "unused", "-o", "unused", "-module", "x=y"},
		{"verified-build", "-policy", "unused", "-manifest", "unused", "-o", "unused", "-backend", "bazel", "-module", "invalid", "//:app"},
	} {
		var out, stderr strings.Builder
		if err := run(args, &out, &stderr); err == nil || exitCode(err) != 2 {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestExistingOutputIsNeverChanged(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "native")
	os.Mkdir(output, 0o755)
	sentinel := filepath.Join(output, "keep")
	os.WriteFile(sentinel, []byte("user contents"), 0o644)
	for _, cmd := range []string{"build", "translate"} {
		var out, errout strings.Builder
		err := run([]string{cmd, "-o", output, "missing.a"}, &out, &errout)
		b, _ := os.ReadFile(sentinel)
		if err == nil || !strings.Contains(err.Error(), "already exists") || string(b) != "user contents" {
			t.Fatalf("existing output modified: %v", err)
		}
	}
}

func TestDoctorJSONReportsMissingToolsWithoutInstalling(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var stdout, stderr strings.Builder
	err := run([]string{"doctor", "-target", "linux/arm64", "-sysroot", t.TempDir(), "-json"}, &stdout, &stderr)
	var result struct {
		Ready  bool
		Checks []doctorCheck
	}
	if parseErr := json.Unmarshal([]byte(stdout.String()), &result); parseErr != nil {
		t.Fatal(parseErr)
	}
	if err == nil || exitCode(err) != 1 || result.Ready || len(result.Checks) != 6 {
		t.Fatalf("doctor did not report failures: %v %+v", err, result)
	}
}
