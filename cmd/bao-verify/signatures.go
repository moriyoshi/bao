package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	auth "github.com/moriyoshi/bao/verify"
)

func (h *harness) signatures() {
	check(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64", "signature integration fixture currently requires Darwin arm64")
	dir := filepath.Join(h.dst, "signature-fixture")
	require(os.Mkdir(dir, 0700))
	module := filepath.Join(dir, "signed-module")
	object := filepath.Join(dir, "leaf.o")
	h.run("signature-producer-rust.log", h.root, nil, "rustc", "--crate-type", "lib", "--emit=obj", "--edition=2024", "-C", "panic=abort", "-O", filepath.Join(h.root, "testdata/leaf.rs"), "-o", object)
	h.run("signature-producer-pack.log", h.root, nil, h.bao, "pack", "-symbol", "bao_leaf_add", "-o", module, object)
	const modulePath = "bao.test/signed-native"
	require(os.WriteFile(filepath.Join(module, "go.mod"), []byte("module "+modulePath+"\ngo 1.26.0\n"), 0644))
	private, public := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	var keys struct {
		KeyID  string `json:"key_id"`
		Public []byte `json:"public_key"`
	}
	require(json.Unmarshal(h.run("signature-keygen.log", dir, nil, h.bao, "keygen", "-private", private, "-public", public), &keys))
	envelope := filepath.Join(dir, "release.json")
	h.run("signature-sign.log", dir, nil, h.bao, "sign", "-root", module, "-module", modulePath, "-target", "darwin/arm64", "-release", "fixture-v1", "-key", private, "-o", envelope)
	var e auth.Envelope
	require(json.Unmarshal(read(envelope), &e))
	policy := auth.Policy{Schema: 1, Keys: map[string][]byte{keys.KeyID: keys.Public}, Approvals: []auth.Approval{{Module: modulePath, Target: "darwin/arm64", Release: "fixture-v1", KeyID: keys.KeyID, PayloadSHA256: auth.Digest(e.Payload)}}}
	policyPath := filepath.Join(dir, "policy.json")
	b, err := json.Marshal(policy)
	require(err)
	require(os.WriteFile(policyPath, b, 0600))
	h.downloadedScan(dir, module, policyPath, envelope)
	app := filepath.Join(dir, "consumer")
	h.module(app, "bao-signature-check", "")
	h.run("signature-replace.log", app, nil, h.goTool, "mod", "edit", "-require="+modulePath+"@v0.0.0", "-replace="+modulePath+"="+module)
	marker := filepath.Join(dir, "init-ran")
	main := fmt.Sprintf(`package main
import("fmt";"os";native %q;"github.com/ebitengine/purego")
func init(){if err:=os.WriteFile(%q,[]byte("executed"),0600);err!=nil{panic(err)}}
func main(){var add func(uint64,uint64)uint64;purego.RegisterFunc(&add,native.SymbolAddr0());if add(19,23)!=42{panic("native failure")};fmt.Println("PASS: signed native module")}
`, modulePath, marker)
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(main), 0644))
	build := func(name, pol, manifest, target string, wantOK bool) {
		output := filepath.Join(dir, name+"-executable")
		out, err := h.command("signature-"+name+".log", app, h.consumerEnv(nil), h.bao, "verified-build", "-go", h.goTool, "-policy", pol, "-manifest", manifest, "-target", target, "-o", output)
		if wantOK {
			require(err)
			check(strings.Contains(string(out), "fresh private GOCACHE"), "no cache policy reported")
		} else {
			check(err != nil, "negative signature control %s accepted", name)
			_, statErr := os.Stat(output)
			check(os.IsNotExist(statErr), "rejected build published executable")
		}
		_, statErr := os.Stat(marker)
		check(os.IsNotExist(statErr), "verification executed consumer init")
	}
	build("approved", policyPath, envelope, "darwin/arm64", true)
	// Populate the ordinary shared Go cache first, then show the outer Bao entry
	// still rejects changed inputs rather than relying on a linker callback.
	h.consumer("signature-warm-shared-cache.log", app, h.goTool, "build", "-o", filepath.Join(dir, "ordinary-executable"), ".")
	build("approved-repeat", policyPath, envelope, "darwin/arm64", true)
	files, err := os.ReadDir(module)
	require(err)
	nativePath := ""
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".syso") {
			nativePath = filepath.Join(module, f.Name())
			break
		}
	}
	check(nativePath != "", "no signed object")
	original := read(nativePath)
	changed := bytes.Clone(original)
	changed[len(changed)-1] ^= 1
	require(os.WriteFile(nativePath, changed, 0644))
	build("changed-native-warm-cache", policyPath, envelope, "darwin/arm64", false)
	require(os.WriteFile(nativePath, original, 0644))
	generated := filepath.Join(module, "symbols_darwin_arm64.go")
	saved := read(generated)
	require(os.WriteFile(generated, append(bytes.Clone(saved), []byte("\nfunc init() { panic(\"untrusted generated binding\") }\n")...), 0644))
	build("changed-go", policyPath, envelope, "darwin/arm64", false)
	require(os.WriteFile(generated, saved, 0644))
	assembly := filepath.Join(module, "symbols_darwin_arm64.s")
	saved = read(assembly)
	require(os.WriteFile(assembly, append(bytes.Clone(saved), []byte("\n// substituted binding\n")...), 0644))
	build("changed-assembly", policyPath, envelope, "darwin/arm64", false)
	require(os.WriteFile(assembly, saved, 0644))
	extra := filepath.Join(module, "extra_darwin_arm64.syso")
	require(os.WriteFile(extra, original, 0644))
	build("extra-native", policyPath, envelope, "darwin/arm64", false)
	require(os.Remove(extra))
	build("wrong-target", policyPath, envelope, "darwin/amd64", false)
	e.Signature[0] ^= 1
	b, err = json.Marshal(e)
	require(err)
	bad := filepath.Join(dir, "bad-signature.json")
	require(os.WriteFile(bad, b, 0600))
	build("bad-signature", policyPath, bad, "darwin/arm64", false)
	policy.Approvals[0].Release = "not-approved"
	b, err = json.Marshal(policy)
	require(err)
	badPolicy := filepath.Join(dir, "bad-policy.json")
	require(os.WriteFile(badPolicy, b, 0600))
	build("wrong-release", badPolicy, envelope, "darwin/arm64", false)
	// Negative control against a real cached package archive, with the unchanged
	// source object still on disk. Mutate its native bytes inside the archive.
	var export struct {
		Export string
		SFiles []string
	}
	require(json.Unmarshal(h.consumer("signature-export.log", app, h.goTool, "list", "-export", "-json", modulePath), &export))
	archive := read(export.Export)
	at := bytes.Index(archive, original)
	check(at >= 0, "actual cache archive lacks original payload")
	archive[at+len(original)-1] ^= 1
	mutated := filepath.Join(dir, "substituted.a")
	require(os.WriteFile(mutated, archive, 0600))
	member := filepath.Base(nativePath)
	if len(member) > 16 {
		member = member[:16]
	}
	inputs := auth.PackageInputs{Native: map[string][]string{member: {auth.Digest(original)}}, GoMembers: map[string]int{"_go_.o": 1}}
	for _, s := range export.SFiles {
		s = strings.TrimSuffix(s, filepath.Ext(s)) + ".o"
		if len(s) > 16 {
			s = s[:16]
		}
		inputs.GoMembers[s]++
	}
	toolDir := strings.TrimSpace(string(h.consumer("signature-tooldir.log", app, h.goTool, "env", "GOTOOLDIR")))
	config := auth.HookConfig{Schema: 1, ToolDirectory: toolDir, Private: dir, Packages: map[string]auth.PackageInputs{modulePath: inputs}, Main: modulePath}
	b, err = json.Marshal(config)
	require(err)
	configPath := filepath.Join(dir, "hook.json")
	require(os.WriteFile(configPath, b, 0600))
	importcfg := filepath.Join(dir, "importcfg")
	require(os.WriteFile(importcfg, nil, 0600))
	out, err := h.command("signature-substituted-archive.log", app, map[string]string{"BAO_VERIFY_CONFIG": configPath}, h.bao, "_verified-tool", filepath.Join(toolDir, "link"), "-importcfg", importcfg, "-o", filepath.Join(dir, "must-not-exist"), mutated)
	check(err != nil && strings.Contains(string(out), "substituted archive member"), "actual archive substitution not rejected: %s", out)
	check(strings.Contains(string(h.consumer("signature-approved-run.log", app, filepath.Join(dir, "approved-executable"))), "PASS: signed native module"), "approved executable failed")
	require(os.Remove(marker))
	// The generated path bundles several assembly files whose ar names share a
	// 16-byte prefix. Verify actual archive multiplicities for that real package.
	staticModule := filepath.Join(dir, "static-module")
	staticSig := filepath.Join(dir, "function-signatures.json")
	require(os.WriteFile(staticSig, []byte(`{"schema":1,"abi":"c","functions":[{"name":"Add","symbol":"bao_leaf_add","params":["uint64","uint64"],"result":"uint64"}]}`), 0600))
	h.run("signature-static-producer.log", dir, nil, h.bao, "translate", "-bindings", staticSig, "-o", staticModule, object)
	const staticPath = "bao.test/static-native"
	require(os.WriteFile(filepath.Join(staticModule, "go.mod"), []byte("module "+staticPath+"\ngo 1.26.0\n"), 0644))
	staticEnvelope := filepath.Join(dir, "static-release.json")
	h.run("signature-static-sign.log", dir, nil, h.bao, "sign", "-root", staticModule, "-module", staticPath, "-target", "darwin/arm64", "-release", "fixture-static-v1", "-key", private, "-o", staticEnvelope)
	var se auth.Envelope
	require(json.Unmarshal(read(staticEnvelope), &se))
	sp := auth.Policy{Schema: 1, Keys: map[string][]byte{keys.KeyID: keys.Public}, Approvals: []auth.Approval{{Module: staticPath, Target: "darwin/arm64", Release: "fixture-static-v1", KeyID: keys.KeyID, PayloadSHA256: auth.Digest(se.Payload)}}}
	spb, err := json.Marshal(sp)
	require(err)
	staticPolicy := filepath.Join(dir, "static-policy.json")
	require(os.WriteFile(staticPolicy, spb, 0600))
	staticApp := filepath.Join(dir, "static-consumer")
	require(os.Mkdir(staticApp, 0755))
	require(os.WriteFile(filepath.Join(staticApp, "go.mod"), []byte("module static-check\ngo 1.26.0\nrequire "+staticPath+" v0.0.0\nreplace "+staticPath+" => "+staticModule+"\n"), 0644))
	require(os.WriteFile(filepath.Join(staticApp, "main.go"), []byte(`package main
import("fmt";native "bao.test/static-native")
func main(){if native.Add(19,23)!=42{panic("static call")};fmt.Println("PASS: verified generated stubs without purego module")}
`), 0644))
	staticExe := filepath.Join(dir, "static-verified-executable")
	h.consumer("signature-static-build.log", staticApp, h.bao, "verified-build", "-go", h.goTool, "-policy", staticPolicy, "-manifest", staticEnvelope, "-target", "darwin/arm64", "-o", staticExe)
	check(strings.Contains(string(h.consumer("signature-static-run.log", staticApp, staticExe)), "PASS: verified generated stubs"), "verified generated bindings failed")
	h.results["signature_verification"] = map[string]any{"status": "PASS", "target": "darwin/arm64", "fixture": "independently generated local test key; no release authority established", "positive": "approved module and repeated request; CGO_ENABLED=0; unavailable C/Rust compilers", "negative": "native byte change with warm shared cache; Go/assembly changes; extra native payload; wrong target/release; bad signature; substituted real cached archive", "execution": "no consumer init during verification; approved executable run separately", "cache": "fresh private per request; actual linker archives copied and authenticated before use"}
	h.results["verified_static_bindings"] = "PASS: complete generated module, bundled bootstrap, no purego dependency; actual archive name collisions counted"
}
