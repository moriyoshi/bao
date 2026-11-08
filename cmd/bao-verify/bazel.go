package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	auth "github.com/moriyoshi/bao/verify"
)

func (h *harness) bazelConsumer() {
	check(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64", "maintained Bazel consumer integration fixture currently runs on Darwin arm64")
	bazel, err := exec.LookPath(h.bazel)
	require(err)
	bazel, err = filepath.Abs(bazel)
	require(err)
	dir := filepath.Join(h.dst, "bazel-fixture")
	workspace := filepath.Join(dir, "consumer")
	require(os.MkdirAll(workspace, 0700))
	native := filepath.Join(workspace, "native")
	object, signatures := filepath.Join(dir, "leaf.o"), filepath.Join(dir, "functions.json")
	h.run("bazel-producer.log", dir, nil, "rustc", "--crate-type", "lib", "--emit=obj", "--edition=2024", "-C", "panic=abort", "-O", filepath.Join(h.root, "testdata/leaf.rs"), "-o", object)
	require(os.WriteFile(signatures, []byte(`{"schema":1,"abi":"c","functions":[{"name":"Add","symbol":"bao_leaf_add","params":["uint64","uint64"],"result":"uint64"}]}`), 0600))
	h.run("bazel-translate.log", dir, nil, h.bao, "translate", "-bindings", signatures, "-o", native, object)
	const module = "bao.test/bazel-native"
	require(os.WriteFile(filepath.Join(native, "go.mod"), []byte("module "+module+"\ngo 1.26.0\n"), 0644))
	require(os.WriteFile(filepath.Join(native, "BUILD.bazel"), []byte(`load("@rules_go//go:def.bzl", "go_library")
go_library(name="native", srcs=glob(["*.go", "*.s", "*.h", "*.syso"]), importpath="bao.test/bazel-native", visibility=["//visibility:public"])
`), 0644))
	require(os.WriteFile(filepath.Join(workspace, "MODULE.bazel"), []byte(`module(name="bao_consumer")
bazel_dep(name="rules_go", version="0.65.0")
go_sdk=use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.download(version="1.26.10")
`), 0644))
	// setup-bazel exposes Bazelisk in CI; the private consumer must select the
	// same pinned release without depending on Bao's parent .bazelversion.
	require(os.WriteFile(filepath.Join(workspace, ".bazelversion"), []byte("8.4.2\n"), 0644))
	build := []byte(`load("@rules_go//go:def.bzl", "go_binary")
go_binary(name="consumer", srcs=["main.go"], deps=["//native"], pure="on", goos="darwin", goarch="arm64")
`)
	require(os.WriteFile(filepath.Join(workspace, "BUILD.bazel"), build, 0644))
	marker := filepath.Join(dir, "init-ran")
	require(os.WriteFile(filepath.Join(workspace, "main.go"), []byte(fmt.Sprintf(`package main
import("fmt";"os"; native %q)
func init(){if err:=os.WriteFile(%q, []byte("ran"), 0600);err!=nil{panic(err)}}
func main(){if native.Add(19,23)!=42{panic("native failure")};fmt.Println("PASS: Bazel consumer verified without purego")}
`, module, marker)), 0644))
	// The ordinary consumer build populates a shared Bazel cache. Its generated
	// lockfile is consumer-trusted input to the subsequent isolated verification.
	startup := []string{bazel, "--batch", "--ignore_all_rc_files", "--output_user_root=" + filepath.Join(dir, "ordinary-cache")}
	h.run("bazel-warm-build.log", workspace, nil, append(append([]string{}, startup...), "build", "--lockfile_mode=update", "//:consumer")...)
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	require(auth.KeyPair(private, public))
	envelope, err := auth.Sign(native, module, "darwin/arm64", "fixture-bazel-v1", private)
	require(err)
	pub, err := auth.ParsePublicKey(read(public))
	require(err)
	policy := auth.Policy{Schema: 1, Keys: map[string][]byte{envelope.KeyID: pub}, Approvals: []auth.Approval{{Module: module, Target: "darwin/arm64", Release: "fixture-bazel-v1", KeyID: envelope.KeyID, PayloadSHA256: auth.Digest(envelope.Payload)}}}
	policyPath, envelopePath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "envelope.json")
	b, err := json.Marshal(policy)
	require(err)
	require(os.WriteFile(policyPath, b, 0600))
	b, err = json.Marshal(envelope)
	require(err)
	require(os.WriteFile(envelopePath, b, 0600))
	invoke := func(name, rejection string) string {
		ok := rejection == ""
		output := filepath.Join(dir, name+"-executable")
		out, err := h.command("bazel-"+name+".log", workspace, nil, h.bao, "verified-build", "-backend", "bazel", "-bazel", bazel, "-module", module+"=native", "-policy", policyPath, "-manifest", envelopePath, "-target", "darwin/arm64", "-o", output, "//:consumer")
		check((err == nil) == ok, "Bazel %s: %v: %s", name, err, out)
		_, statErr := os.Stat(marker)
		check(os.IsNotExist(statErr), "Bazel verifier ran consumer init")
		if !ok {
			check(strings.Contains(string(out), rejection), "Bazel %s failed for the wrong reason: %s", name, out)
			_, statErr = os.Stat(output)
			check(os.IsNotExist(statErr), "rejected Bazel build published output")
		}
		return output
	}
	// Poison a real ordinary-cache native archive, while leaving signed source
	// untouched. The verified build must use newly compiled private archives.
	var graph struct {
		Actions []struct {
			Mnemonic  string
			Arguments []string
		}
	}
	b = h.run("bazel-warm-aquery.log", workspace, nil, append(append([]string{}, startup...), "aquery", "--output=jsonproto", "deps(//:consumer)")...)
	require(json.Unmarshal(b, &graph))
	execroot := strings.TrimSpace(string(h.run("bazel-warm-execroot.log", workspace, nil, append(append([]string{}, startup...), "info", "execution_root")...)))
	poisoned := false
	for _, action := range graph.Actions {
		if action.Mnemonic != "GoCompilePkg" {
			continue
		}
		var path string
		nativeAction := false
		for i := 0; i+1 < len(action.Arguments); i++ {
			if action.Arguments[i] == "-p" && action.Arguments[i+1] == module {
				nativeAction = true
			}
			if action.Arguments[i] == "-lo" {
				path = action.Arguments[i+1]
			}
		}
		if !nativeAction {
			continue
		}
		path = filepath.Join(execroot, path)
		b = read(path)
		syso, err := filepath.Glob(filepath.Join(native, "*.syso"))
		require(err)
		check(len(syso) != 0, "no native fixture objects")
		payload := read(syso[0])
		at := bytes.Index(b, payload)
		check(at >= 0, "ordinary archive lacks native payload")
		b[at+len(payload)-1] ^= 1
		require(os.Chmod(path, 0600))
		require(os.WriteFile(path, b, 0600))
		poisoned = true
	}
	check(poisoned, "ordinary Bazel archive was not poisoned")
	approved := invoke("approved-with-poisoned-shared-cache", "")
	// Pick a generated Go source rather than relying on a particular filename.
	goFiles, err := filepath.Glob(filepath.Join(native, "*.go"))
	require(err)
	check(len(goFiles) > 0, "no Go fixture source")
	goPath := goFiles[0]
	saved := read(goPath)
	require(os.WriteFile(goPath, append(bytes.Clone(saved), []byte("\n// source changed\n")...), 0644))
	invoke("changed-signed-source", "signed bytes differ")
	require(os.WriteFile(goPath, saved, 0644))
	require(os.WriteFile(filepath.Join(workspace, "BUILD.bazel"), append(bytes.Clone(build), []byte(`genrule(name="unapproved_action", outs=["custom"], cmd="echo forbidden > $@")
`)...), 0644))
	// Make the unsupported action reachable from the selected executable.
	b = bytes.Replace(read(filepath.Join(workspace, "BUILD.bazel")), []byte(`pure="on"`), []byte(`data=[":unapproved_action"], pure="on"`), 1)
	require(os.WriteFile(filepath.Join(workspace, "BUILD.bazel"), b, 0644))
	invoke("unsupported-custom-action", "unsupported Bazel action Genrule")
	check(strings.Contains(string(h.run("bazel-approved-run.log", workspace, nil, approved)), "PASS: Bazel consumer"), "verified Bazel executable failed")
	h.results["bazel_verified_consumer"] = map[string]any{"status": "PASS", "target": "darwin/arm64", "positive": "independent rules_go consumer; bundled stubs; shared archive poisoned; private checked replay", "negative": "changed signed source; reachable custom action; no init/output on rejection", "execution": "native; approved executable run separately", "cache": "fresh private Bazel/Go roots; no action-result reuse"}
}
