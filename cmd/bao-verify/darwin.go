package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var darwinExamples = []string{"core_foundation", "core_graphics", "core_text", "security", "image_io", "foundation", "accelerate", "rust_runtime"}

func (h *harness) darwin() {
	check(runtime.GOOS == "darwin" && (h.target == "darwin/arm64" || h.target == "darwin/amd64"), "Darwin suite requires a supported macOS host/target")
	arch := strings.TrimPrefix(h.target, "darwin/")
	h.env["GOOS"] = "darwin"
	h.env["GOARCH"] = arch
	h.results["target"] = h.target
	if runtime.GOARCH != arch {
		h.results["execution"] = "Rosetta 2 translation on macOS/" + runtime.GOARCH
	} else {
		h.results["execution"] = "native " + h.target
	}
	version := strings.TrimSpace(string(h.run("rust-version.log", h.root, nil, "rustc", "--version")))
	check(strings.HasPrefix(version, "rustc 1.99.1 "), "requires Rust 1.99.1; got %s", version)
	h.results["rust"] = version
	for _, cmd := range []string{"build", "translate", "doctor", "inspect", "targets", "version", "pack"} {
		h.run("help-"+cmd+".log", h.root, nil, h.bao, "help", cmd)
	}
	var doctor map[string]any
	require(json.Unmarshal(h.run("doctor.json", h.root, nil, h.bao, "doctor", "-target", h.target, "-json"), &doctor))
	check(doctor["ready"] == true, "producer toolchain is not ready")
	sdk := strings.TrimSpace(string(h.run("sdk.log", h.root, nil, "xcrun", "--show-sdk-path")))
	sdkVersion := strings.TrimSpace(string(h.run("sdk-version.log", h.root, nil, "xcrun", "--show-sdk-version")))
	results := map[string]any{}
	for _, name := range darwinExamples {
		fmt.Println("Checking", name)
		app := filepath.Join(h.dst, name)
		require(os.Mkdir(app, 0o755))
		args := []string{h.bao, "build", "-target", h.target, "-manifest-path", filepath.Join(h.root, "examples", name, "Cargo.toml"), "-offline", "-locked", "-symbol", "bao_example_run", "-o", filepath.Join(app, "native"), "-json"}
		if name == "rust_runtime" {
			args = append(args, "-symbol", "bao_example_check_finalized")
		}
		h.run(name+"-producer.log", h.root, nil, args...)
		h.module(app, "bao-example-check", "")
		copyFile(filepath.Join(h.root, "examples/consumer/main.go.tmpl"), filepath.Join(app, "main.go"))
		finalizer := "func checkFinalized() {}\n"
		if name == "rust_runtime" {
			finalizer = `import (
    "bao-example-check/native"
    "github.com/ebitengine/purego"
)
func checkFinalized() {
    var check func() uint64
    purego.RegisterFunc(&check, native.SymbolAddr1())
    if check() != 42 || native.TLSDestroyedBlocks() != 9 { panic("TLS destructor count") }
}
`
		}
		require(os.WriteFile(filepath.Join(app, "config.go"), []byte("package main\n"+finalizer+"\nconst exampleName = "+fmt.Sprintf("%q", name)+"\n"), 0o644))
		manifest := readJSON(filepath.Join(app, "native/bao-manifest.json"))
		modes := map[string]any{"cargo": h.darwinConsumer(app, name+"-cargo", name, name == "rust_runtime")}
		if name == "core_graphics" {
			provenance := readJSON(filepath.Join(app, "native/bao-build.json"))
			archive := provenance["source"].(string)
			check(digest(archive) == provenance["source_sha256"], "source archive hash changed")
			output := filepath.Join(app, "archive output")
			h.run("archive-producer.log", h.root, nil, h.bao, "build", "-sdk", sdk, "-symbol", "bao_example_run", "-o", output, archive)
			require(os.RemoveAll(filepath.Join(app, "native")))
			require(os.Rename(output, filepath.Join(app, "native")))
			modes["archive"] = h.darwinConsumer(app, name+"-archive", name, false)
			combined := filepath.Join(h.dst, "combined.o")
			ldarch := "arm64"
			if arch == "amd64" {
				ldarch = "x86_64"
			}
			h.run("manual-combine.log", h.root, nil, "/usr/bin/ld", "-r", "-arch", ldarch, "-platform_version", "macos", "11.0", sdkVersion, "-all_load", archive, "-o", combined)
			h.run("inspect.json", h.root, nil, h.bao, "inspect", combined)
			output = filepath.Join(app, "object output")
			h.consumer("object-producer.log", h.root, h.bao, "translate", "-sdk", sdk, "-symbol", "bao_example_run", "-o", output, combined)
			require(os.RemoveAll(filepath.Join(app, "native")))
			require(os.Rename(output, filepath.Join(app, "native")))
			modes["object"] = h.darwinConsumer(app, name+"-object", name, false)
			before := digest(filepath.Join(app, "native/bao-manifest.json"))
			_, err := h.command("refuse-overwrite.log", h.root, nil, h.bao, "build", "-o", filepath.Join(app, "native"), "missing.a")
			check(err != nil && digest(filepath.Join(app, "native/bao-manifest.json")) == before, "build overwrote existing output")
		}
		if name == "rust_runtime" {
			negative := filepath.Join(h.dst, "negative-unwind")
			copyTree(app, negative)
			path := filepath.Join(negative, "native/symbols_darwin_"+arch+".go")
			source := string(read(path))
			check(strings.Contains(source, "registerFrame("), "no unwind registration to disable")
			require(os.WriteFile(path, []byte(strings.ReplaceAll(source, "registerFrame(", "func(uintptr) {}(")), 0o644))
			exe := filepath.Join(h.dst, "negative-executable")
			h.consumer("negative-link.log", negative, h.goTool, "build", "-o", exe, ".")
			out, err := h.command("negative-run.log", negative, nil, exe)
			check(err != nil && strings.Contains(string(out), "failed to initiate panic") && !strings.Contains(string(out), "PASS:"), "no-unwind negative control was not detected")
		}
		results[name] = map[string]any{"modes": modes, "tls_descriptors": manifest["tls_descriptors"], "tls_alignment": manifest["tls_template_alignment"], "compact_frames": manifest["compact_frames_synthesized"]}
		fmt.Println("PASS", name)
	}
	h.results["darwin_examples"] = results
	h.results["unwind_negative_control"] = "PASS"
	h.darwinDylib(arch, sdk)
	h.darwinDylibObjC(arch, sdk)
}

func (h *harness) darwinConsumer(app, prefix, expected string, aligned bool) map[string]any {
	exe := filepath.Join(h.dst, prefix+"-executable")
	h.consumer(prefix+"-build.log", app, h.goTool, "build", "-o", exe, ".")
	info := string(h.run(prefix+"-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0") && strings.Contains(info, puregoVersion) && !strings.Contains(info, "=>"), "consumer must use cgo-disabled Go and the downloaded purego module")
	for _, procs := range []string{"1", "4"} {
		out := h.run(prefix+"-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe)
		check(strings.Contains(string(out), "PASS: "+expected+";"), "native check failed")
	}
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-example-check", aligned)
	h.saveJSON(prefix+"-alignment.json", alignment)
	h.run(prefix+"-sign.log", app, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
	h.run(prefix+"-verify.log", app, nil, "codesign", "--verify", "--strict", exe)
	check(strings.Contains(string(h.consumer(prefix+"-signed-run.log", app, exe)), "PASS: "+expected+";"), "signed native check failed")
	return map[string]any{"status": "PASS", "alignments_checked": len(alignment), "executable_sha256": digest(exe)}
}
