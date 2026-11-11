package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBazelArchiveProfileAndNativeMultiplicity(t *testing.T) {
	type member = struct {
		name string
		data []byte
	}
	goObject := []byte("go object linux arm64 go1.26.11 fixture\n")
	native := []byte{0x7f, 'E', 'L', 'F', 1, 2}
	expected := PackageInputs{Native: map[string][]string{"native.syso": {Digest(native), Digest(native)}}, GoMembers: map[string]int{"_go_.o": 1, "s0.o": 1}}
	base := []member{{"_go_.o", goObject}, {"s0.o", goObject}, {"native.syso", native}, {"native.syso", native}}
	if n, err := bazelCheckArchive(archiveFixture(base...), expected, "linux/arm64"); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if _, err := CheckArchive(archiveFixture(base...), expected); err == nil {
		t.Fatal("cmd/go profile must still require PKGDEF")
	}
	for _, kind := range []string{"native-change", "native-missing", "native-extra", "assembly-missing", "assembly-extra", "pkgdef", "wrong-sdk", "wrong-target", "native-as-go"} {
		t.Run(kind, func(t *testing.T) {
			m := append([]member(nil), base...)
			switch kind {
			case "native-change":
				m[2].data = []byte("substituted ELF")
			case "native-missing":
				m = m[:3]
			case "native-extra":
				m = append(m, base[2])
			case "assembly-missing":
				m = append(m[:1], m[2:]...)
			case "assembly-extra":
				m = append(m, base[1])
			case "pkgdef":
				m = append(m, member{"__.PKGDEF", goObject})
			case "wrong-sdk":
				m[0].data = []byte("go object linux arm64 go1.26.5 fixture\n")
			case "wrong-target":
				m[1].data = []byte("go object linux amd64 go1.26.11 fixture\n")
			case "native-as-go":
				m[1].data = native
			}
			if _, err := bazelCheckArchive(archiveFixture(m...), expected, "linux/arm64"); err == nil {
				t.Fatal("unsupported archive accepted")
			}
		})
	}
}

func bazelTestAction(t *testing.T, mnemonic string, args []string) bazelAction {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"mnemonic": mnemonic, "arguments": args, "environmentVariables": []map[string]string{{"key": "GOOS", "value": "linux"}, {"key": "GOARCH", "value": "arm64"}, {"key": "CGO_ENABLED", "value": "0"}}})
	var a bazelAction
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func bazelTestLink(t *testing.T) bazelAction {
	return bazelTestAction(t, "GoLink", []string{"builder", "link", "-sdk", "sdk", "-goroot", "stdlib", "-installsuffix", "linux_arm64", "-arc", "//native:native=test/native=out/native.a", "-package_list", "packages.txt", "-o", "out/executable", "-main", "out/main.a", "-p", "main", "--", "-linkmode", "internal", "-s", "-w"})
}

func bazelWrite(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBazelGraphSelectsAssemblyAndRejectsUnapprovedSources(t *testing.T) {
	root := t.TempDir()
	bazelWrite(t, root, "native/native_linux_arm64.syso", []byte("ELF"))
	bazelWrite(t, root, "native/good_linux_arm64.s", []byte("//go:build linux && arm64\n\n"))
	bazelWrite(t, root, "native/other_linux_amd64.s", []byte("//go:build linux && amd64\n\n"))
	args := []string{"builder", "compilepkg", "-installsuffix", "linux_arm64", "-src", "native/native_linux_arm64.syso", "-src", "native/good_linux_arm64.s", "-src", "native/other_linux_amd64.s", "-p", "test/native", "-lo", "out/native.a", "-gcflags", ""}
	graph := bazelGraph{Actions: []bazelAction{bazelTestAction(t, "GoCompilePkg", args), bazelTestLink(t)}}
	_, packages, err := bazelCheckGraph(graph, root, "linux/arm64", map[string]string{"test/native": "native"})
	if err != nil {
		t.Fatal(err)
	}
	if got := packages["out/native.a"].inputs.GoMembers; got["s0.o"] != 1 || len(got) != 2 {
		t.Fatal("assembly selection must honor target/build constraints", got)
	}
	for _, kind := range []string{"unapproved", "external", "escape", "extra-source", "genrule", "compiler-flags", "external-link", "two-links", "cgo"} {
		t.Run(kind, func(t *testing.T) {
			g := bazelGraph{Actions: append([]bazelAction(nil), graph.Actions...)}
			g.Actions[0].Arguments = append([]string(nil), args...)
			roots := map[string]string{"test/native": "native"}
			switch kind {
			case "unapproved":
				roots = nil
			case "external":
				g.Actions[0].Arguments[5] = "external/native/object.syso"
			case "escape":
				g.Actions[0].Arguments[5] = "../native/object.syso"
			case "extra-source":
				g.Actions[0].Arguments = append(g.Actions[0].Arguments, "-src", "outside.go")
			case "genrule":
				g.Actions = append(g.Actions, bazelAction{Mnemonic: "Genrule"})
			case "compiler-flags":
				g.Actions[0].Arguments[len(args)-1] = "-importcfg=/unapproved"
			case "external-link":
				g.Actions[1].Arguments = append([]string(nil), g.Actions[1].Arguments...)
				g.Actions[1].Arguments[len(g.Actions[1].Arguments)-3] = "external"
			case "two-links":
				g.Actions = append(g.Actions, bazelTestLink(t))
			case "cgo":
				g.Actions[0] = bazelTestAction(t, "GoCompilePkg", append(append([]string(nil), args...), "-src", "native.c"))
			}
			if _, _, err := bazelCheckGraph(g, root, "linux/arm64", roots); err == nil {
				t.Fatal("unsupported graph accepted")
			}
		})
	}
}

func TestBazelPrivateLinkUsesCheckedCopies(t *testing.T) {
	root, work := t.TempDir(), t.TempDir()
	goObject := []byte("go object linux arm64 go1.26.11 fixture\n")
	native := []byte("signed native bytes")
	a := archiveFixture(struct {
		name string
		data []byte
	}{"_go_.o", goObject}, struct {
		name string
		data []byte
	}{"native.syso", native})
	main := archiveFixture(struct {
		name string
		data []byte
	}{"_go_.o", goObject})
	bazelWrite(t, root, "builder", []byte("trusted builder"))
	bazelWrite(t, root, "sdk/pkg/tool/darwin_arm64/link", []byte("trusted linker"))
	bazelWrite(t, root, "stdlib/pkg/linux_arm64/runtime.a", main)
	bazelWrite(t, root, "packages.txt", []byte("runtime\n"))
	bazelWrite(t, root, "out/native.a", a)
	bazelWrite(t, root, "out/main.a", main)
	packages := map[string]bazelPackage{"out/native.a": {path: "test/native", inputs: PackageInputs{Native: map[string][]string{"native.syso": {Digest(native)}}, GoMembers: map[string]int{"_go_.o": 1}}}, "out/main.a": {path: "main", inputs: PackageInputs{GoMembers: map[string]int{"_go_.o": 1}}}}
	args, report, err := bazelPrivateLink(root, work, bazelTestLink(t), packages)
	if err != nil {
		t.Fatal(err)
	}
	if report.NativeMembers != 1 || len(report.Archives) != 2 {
		t.Fatal(report)
	}
	arc, _ := bazelValue(args, "-arc")
	path := strings.SplitN(arc, "=", 3)[2]
	bazelWrite(t, root, "out/native.a", []byte("substituted after check"))
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("link action did not retain the checked archive bytes", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("checked archive is not private read-only", err)
	}
	if _, _, err = bazelPrivateLink(root, t.TempDir(), bazelTestLink(t), packages); err == nil {
		t.Fatal("substituted actual archive accepted")
	}
}

func TestBazelSnapshotRejectsLinksAndKeepsSignedBuildMetadata(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	bazelWrite(t, root, "native/BUILD.bazel", []byte("signed metadata"))
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "bazel-out")); err != nil {
		t.Fatal(err)
	}
	if err := bazelSnapshot(root, out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "native", "BUILD.bazel")); err != nil || string(b) != "signed metadata" {
		t.Fatal("snapshot omitted signed BUILD", err)
	}
	if err := os.Symlink("BUILD.bazel", filepath.Join(root, "native", "alias")); err != nil {
		t.Fatal(err)
	}
	if err := bazelSnapshot(root, t.TempDir()); err == nil {
		t.Fatal("native source symlink accepted")
	}
}

func TestBazelAuthenticatesBuildMetadataBeforeExecutingBazel(t *testing.T) {
	native, envelope, policy := signedFixture(t)
	workspace := t.TempDir()
	if _, err := Tree(native, filepath.Join(workspace, "native")); err != nil {
		t.Fatal(err)
	}
	bazelWrite(t, workspace, "native/BUILD.bazel", []byte("unapproved publisher metadata"))
	marker := filepath.Join(t.TempDir(), "bazel-executed")
	script := filepath.Join(t.TempDir(), "bazel")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n: > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := BazelBuild(context.Background(), BazelOptions{Directory: workspace, Bazel: script, Target: "darwin/arm64", Package: "//:app", Output: filepath.Join(t.TempDir(), "app"), Policy: policy, Envelopes: []Envelope{envelope}, ModuleRoots: map[string]string{"test.invalid/native": "native"}})
	if err == nil || !strings.Contains(err.Error(), "file set differs") {
		t.Fatal("changed signed BUILD metadata was not rejected", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("Bazel ran before source authentication")
	}
}

func TestBazelMnemonicDoesNotAuthenticateExecutables(t *testing.T) {
	link := bazelTestLink(t)
	link.Arguments[0] = "bazel-out/host/bin/external/rules_go++go_sdk+main___download_0/builder_reset/builder"
	for i, arg := range link.Arguments {
		if arg == "-sdk" {
			link.Arguments[i+1] = "external/rules_go++go_sdk+main___download_0"
		}
		if arg == "-goroot" {
			link.Arguments[i+1] = "bazel-out/target/bin/external/rules_go+/stdlib_"
		}
	}
	b, _ := json.Marshal(link)
	var data map[string]any
	_ = json.Unmarshal(b, &data)
	data["environmentVariables"] = []map[string]string{{"key": "CGO_ENABLED", "value": "0"}, {"key": "GOTOOLCHAIN", "value": "local"}, {"key": "GOROOT_FINAL", "value": "GOROOT"}}
	b, _ = json.Marshal(data)
	_ = json.Unmarshal(b, &link)
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{link}}, link); err != nil {
		t.Fatal(err)
	}
	sdk, _ := bazelValue(link.Arguments, "-sdk")
	stdlib, _ := bazelValue(link.Arguments, "-goroot")
	compile := link
	compile.Mnemonic = "GoCompilePkg"
	pack := "bazel-out/host/bin/" + sdk + "/pack_reset/pack.exe"
	compile.Arguments = []string{link.Arguments[0], "compilepkg", "-sdk", sdk, "-goroot", stdlib, "-pack", pack}
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{compile, link}}, link); err != nil {
		t.Fatal(err)
	}
	compile.Arguments[len(compile.Arguments)-1] = "bazel-out/host/bin/native/nested/bin/" + sdk + "/pack_reset/pack.exe"
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{compile, link}}, link); err == nil {
		t.Fatal("nested lookalike packer path accepted")
	}
	spoof := link
	spoof.Arguments = append([]string(nil), link.Arguments...)
	spoof.Arguments[0] = "native/untrusted-executable"
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{spoof}}, link); err == nil {
		t.Fatal("GoLink mnemonic authenticated an arbitrary executable")
	}
	bootstrap := bazelAction{Mnemonic: "GoToolchainBinaryBuild", Arguments: []string{"native/launcher", "pack", "cov", "builder", "native/code.go"}}
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{bootstrap}}, link); err == nil {
		t.Fatal("Go bootstrap mnemonic authenticated arbitrary code")
	}
}

func TestBazelDarwinPIEFlagsAreNarrow(t *testing.T) {
	for _, suffix := range []string{"darwin_arm64", "darwin_amd64", "linux_arm64"} {
		args := append([]string(nil), bazelTestLink(t).Arguments...)
		for i, arg := range args {
			if arg == "-installsuffix" {
				args[i+1] = suffix
			}
		}
		idx := 0
		for i, arg := range args {
			if arg == "--" {
				idx = i
			}
		}
		args = append(args[:idx], append([]string{"-buildmode", "pie"}, args[idx:]...)...)
		err := bazelLinkFlags(args)
		if (suffix != "linux_arm64") != (err == nil) {
			t.Fatalf("%s PIE: %v", suffix, err)
		}
		args[idx+1] = "plugin"
		if bazelLinkFlags(args) == nil {
			t.Fatal("plugin mode accepted")
		}
		compile := []string{"builder", "compilepkg", "-installsuffix", suffix, "-gcflags", "-shared", "-asmflags", "-shared"}
		if err := bazelCompileFlags(compile); (suffix != "linux_arm64") != (err == nil) {
			t.Fatalf("%s shared compile flags: %v", suffix, err)
		}
		compile[len(compile)-1] = "-I /unapproved"
		if bazelCompileFlags(compile) == nil {
			t.Fatal("arbitrary assembler flags accepted")
		}
	}
}

func TestBazelBootstrapEnvironmentCannotReplaceTrustedGo(t *testing.T) {
	link := bazelTestLink(t)
	sdk := "external/rules_go++go_sdk+main___download_0"
	link.Arguments[0] = "bazel-out/host/bin/" + sdk + "/builder_reset/builder"
	for i, arg := range link.Arguments {
		if arg == "-sdk" {
			link.Arguments[i+1] = sdk
		}
		if arg == "-goroot" {
			link.Arguments[i+1] = "bazel-out/target/bin/external/rules_go+/stdlib_"
		}
	}
	bootstrap := bazelAction{Mnemonic: "GoToolchainBinaryBuild", Arguments: []string{"external/rules_go+/go/private/rules/binary_wrapper.sh", "bazel-out/host/bin/" + sdk + "/pack.exe", "bazel-out/host/bin/" + sdk + "/covdata.exe", "bazel-out/host/bin/" + sdk + "/builder", "external/rules_go+/go/tools/builders/main.go"}}
	for key, value := range map[string]string{"GO_BINARY": sdk + "/bin/go", "LD_FLAGS": "-X main.rulesGoStdlibPrefix=@@rules_go+//stdlib:", "GOENV": "off", "GOTOOLCHAIN": "local", "GO111MODULE": "off", "GOEXPERIMENT": "", "GOMAXPROCS": "1", "GOTELEMETRY": "off"} {
		bootstrap.EnvironmentVariables = append(bootstrap.EnvironmentVariables, struct{ Key, Value string }{key, value})
	}
	if err := bazelCheckTools(bazelGraph{Actions: []bazelAction{bootstrap}}, link); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GO_BINARY", "LD_FLAGS", "GOENV", "GOTOOLCHAIN"} {
		changed := bootstrap
		changed.EnvironmentVariables = append([]struct{ Key, Value string }(nil), bootstrap.EnvironmentVariables...)
		for i, pair := range changed.EnvironmentVariables {
			if pair.Key == key {
				changed.EnvironmentVariables[i].Value = "unapproved-native-launcher"
			}
		}
		if bazelCheckTools(bazelGraph{Actions: []bazelAction{changed}}, link) == nil {
			t.Fatal("bootstrap environment override accepted", key)
		}
	}
}
