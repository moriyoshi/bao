package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCargoUsesSelectedArtifactAndProjectConfiguration(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "Cargo.toml")
	if err := os.WriteFile(manifest, []byte("[package]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, _ = filepath.EvalSymlinks(manifest)
	link := filepath.Join(root, "alias.toml")
	if err := os.Symlink(manifest, link); err != nil {
		t.Fatal(err)
	}
	target, _ := ParseTarget("darwin/arm64")
	artifact := filepath.Join(root, "custom output", "actually_named_library.a")
	var commands []Command
	run := func(_ context.Context, c Command) ([]byte, error) {
		commands = append(commands, c)
		if len(commands) == 1 {
			return json.Marshal(map[string]any{"workspace_members": []string{"selected", "other"}, "packages": []any{
				map[string]any{"id": "selected", "name": "example", "manifest_path": manifest, "targets": []any{map[string]any{"name": "custom_name", "crate_types": []string{"staticlib"}}}},
				map[string]any{"id": "other", "name": "other", "manifest_path": filepath.Join(root, "other/Cargo.toml"), "targets": []any{map[string]any{"name": "other", "crate_types": []string{"staticlib"}}}},
			}})
		}
		return []byte(`{"reason":"compiler-artifact","package_id":"other","target":{"name":"other"},"filenames":["/wrong/dependency.a"]}` + "\n" +
			`{"reason":"compiler-message","message":{"rendered":"example warning\n"}}` + "\n" +
			`{"reason":"compiler-artifact","package_id":"selected","target":{"name":"custom_name"},"filenames":[` + stringMustJSON(artifact) + `]}` + "\n"), nil
	}
	var diagnostics strings.Builder
	got, err := CargoArchive(context.Background(), run, CargoOptions{Manifest: link, Target: target, Offline: true, Locked: true}, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if got != artifact || diagnostics.String() != "example warning\n" {
		t.Fatalf("wrong artifact/diagnostics: %s %s", got, diagnostics.String())
	}
	for _, c := range commands {
		if c.Dir != filepath.Dir(manifest) || !contains(c.Args, "--offline") || !contains(c.Args, "--locked") {
			t.Fatalf("project/offline configuration lost: %+v", c)
		}
	}
	if !contains(commands[1].Args, target.RustTriple) {
		t.Fatal("Cargo built for the host instead of the selected target")
	}
}

func stringMustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestAmbiguousWorkspaceDoesNotStartBuild(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "Cargo.toml")
	os.WriteFile(manifest, nil, 0o644)
	calls := 0
	run := func(_ context.Context, c Command) ([]byte, error) {
		calls++
		return []byte(`{"workspace_members":["a","b"],"packages":[{"id":"a","name":"a","manifest_path":"/a/Cargo.toml","targets":[{"name":"a","crate_types":["staticlib"]}]},{"id":"b","name":"b","manifest_path":"/b/Cargo.toml","targets":[{"name":"b","crate_types":["staticlib"]}]}]}`), nil
	}
	_, err := CargoArchive(context.Background(), run, CargoOptions{Manifest: manifest}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "2 staticlib") || calls != 1 {
		t.Fatalf("ambiguous Cargo workspace was built: calls=%d err=%v", calls, err)
	}
}

func TestCargoFailureRendersDiagnosticAndKeepsFailure(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "Cargo.toml")
	os.WriteFile(manifest, nil, 0o644)
	manifest, _ = filepath.EvalSymlinks(manifest)
	failure := errors.New("compiler failed")
	run := func(_ context.Context, c Command) ([]byte, error) {
		if c.Args[0] == "metadata" {
			return []byte(`{"workspace_members":["a"],"packages":[{"id":"a","name":"a","manifest_path":` + stringMustJSON(manifest) + `,"targets":[{"name":"a","crate_types":["staticlib"]}]}]}`), nil
		}
		return []byte(`{"reason":"compiler-message","message":{"rendered":"source.rs: error: broken input\n"}}` + "\n"), failure
	}
	var diagnostics strings.Builder
	_, err := CargoArchive(context.Background(), run, CargoOptions{Manifest: manifest}, &diagnostics)
	if !errors.Is(err, failure) || !strings.Contains(diagnostics.String(), "broken input") {
		t.Fatalf("lost compiler failure: %v %s", err, diagnostics.String())
	}
}

func TestInterruptedCargoDoesNotMaskCancellationWithPartialJSON(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "Cargo.toml")
	if err := os.WriteFile(manifest, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, _ = filepath.EvalSymlinks(manifest)
	run := func(_ context.Context, c Command) ([]byte, error) {
		if c.Args[0] == "metadata" {
			return []byte(`{"workspace_members":["a"],"packages":[{"id":"a","name":"a","manifest_path":` + stringMustJSON(manifest) + `,"targets":[{"name":"a","crate_types":["staticlib"]}]}]}`), nil
		}
		return []byte(`{"reason":"compiler-message"`), context.Canceled
	}
	_, err := CargoArchive(context.Background(), run, CargoOptions{Manifest: manifest}, &strings.Builder{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was masked: %v", err)
	}
}

func TestCombineUsesSDKVersionAndLiteralPaths(t *testing.T) {
	root := t.TempDir()
	sdk := filepath.Join(root, "SDK with spaces")
	os.Mkdir(sdk, 0o755)
	os.WriteFile(filepath.Join(sdk, "SDKSettings.json"), []byte(`{"Version":"26.5"}`), 0o644)
	input := filepath.Join(root, "-lib$(touch should_not_exist).a")
	var command Command
	target, _ := ParseTarget("darwin/arm64")
	err := Combine(context.Background(), func(_ context.Context, c Command) ([]byte, error) { command = c; return nil, nil }, target, "chosen-ld", sdk, "11.0", input, filepath.Join(root, "combined.o"))
	if err != nil {
		t.Fatal(err)
	}
	if command.Tool != "chosen-ld" || !contains(command.Args, input) || !contains(command.Args, "26.5") {
		t.Fatalf("paths/version lost: %+v", command)
	}
	if _, err := os.Stat(filepath.Join(root, "should_not_exist")); !os.IsNotExist(err) {
		t.Fatal("shell substitution was executed")
	}
}
