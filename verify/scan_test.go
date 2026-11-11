package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDependencyScanScopeAndRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix resolver protocol fixture")
	}
	root, envelope, policy := signedFixture(t)
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "init.go"), []byte("package plain;func init(){panic(\"must never execute\")}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "modules.json")
	modules := []scanModule{{Path: "consumer.invalid/app", Main: true, Dir: t.TempDir()},
		{Path: "test.invalid/native", Version: "v1.0.0", Replace: &scanModule{Dir: root}},
		{Path: "test.invalid/plain", Dir: plain}, {Path: "test.invalid/missing", Version: "v1.0.0"}}
	var stream strings.Builder
	for _, m := range modules {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(b)
		stream.WriteByte('\n')
	}
	if err := os.WriteFile(list, []byte(stream.String()), 0600); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, "go")
	// This fixture permits only source resolution and cache integrity commands.
	// The integration harness separately exercises the actual pinned Go resolver.
	if err := os.WriteFile(tool, []byte(`#!/bin/sh
set -eu
[ "$CGO_ENABLED" = 0 ] && [ "$GOPROXY" = off ] && [ "$GOWORK" = off ] && [ "$GOTOOLCHAIN" = local ] && [ "$GOENV" = off ]
case "$*" in
  'env GOVERSION') echo go1.26.11 ;;
  'list -m -mod=readonly -json all') cat "$BAO_SCAN_FIXTURE" ;;
  'mod verify') echo 'all modules verified' ;;
  *) echo 'unexpected build or execution command' >&2; exit 9 ;;
esac
`), 0700); err != nil {
		t.Fatal(err)
	}
	// buildEnv deliberately does not carry arbitrary fixture variables.
	b, err := os.ReadFile(tool)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.ReplaceAll(string(b), `"$BAO_SCAN_FIXTURE"`, "'"+strings.ReplaceAll(list, "'", "'\\''")+"'"))
	if err := os.WriteFile(tool, b, 0700); err != nil {
		t.Fatal(err)
	}
	caller, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeTool, err := filepath.Rel(caller, tool)
	if err != nil {
		t.Fatal(err)
	}
	// The explicit tool path is relative to Bao's caller, not -C's directory.
	opts := ScanOptions{Directory: dir, Go: relativeTool, Target: "darwin/arm64", Policy: policy, Envelopes: []Envelope{envelope}}
	report, err := Scan(context.Background(), opts)
	if err != nil || report.MainModule != "consumer.invalid/app" || len(report.Modules) != 3 || len(report.Authenticated) != 1 || report.Modules[0].Status != "not-downloaded" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if report.Modules[1].Status != "authenticated" || !report.Modules[1].Replacement {
		t.Fatalf("local replacement: %+v", report.Modules[1])
	}
	// Scan every downloaded .syso, including another target and an unused package.
	if err := os.Mkdir(filepath.Join(plain, "unused"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plain, "unused", "payload_linux_ppc64le.syso"), []byte("unapproved"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = Scan(context.Background(), opts)
	if err == nil || report.NativeFiles != 1 || report.Modules[2].Status != "unapproved-native-inputs" {
		t.Fatalf("unsigned native accepted: %+v %v", report, err)
	}
	if err := os.RemoveAll(filepath.Join(plain, "unused")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binding.go"), []byte("substituted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), opts); err == nil {
		t.Fatal("modified signed tree accepted")
	}
	opts.Policy, opts.Envelopes = Policy{}, nil
	if _, err := Scan(context.Background(), opts); err != nil {
		t.Fatalf("ordinary non-native dependencies require no policy: %v", err)
	}
	opts.Policy, opts.Envelopes = policy, []Envelope{envelope}
	if err := os.WriteFile(list, []byte(`{"Path":"consumer.invalid/app","Main":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "absent or not downloaded") {
		t.Fatalf("missing approved dependency: %v", err)
	}
}
