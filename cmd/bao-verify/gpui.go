package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func (h *harness) gpuiCheck() {
	check(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64", "GPUI integration requires macOS arm64")
	check(h.gpui != "", "-suite gpui requires -gpui-root")
	root, err := filepath.Abs(h.gpui)
	require(err)
	archive := filepath.Join(root, "target/release/libgpui_go_native.a")
	before := digest(archive)
	app := filepath.Join(h.dst, "gpui")
	require(os.Mkdir(app, 0o755))
	copyFile(filepath.Join(h.root, "testdata/headless/main.go"), filepath.Join(app, "main.go"))
	protobuf := regexp.MustCompile(`google.golang.org/protobuf\s+(v\S+)`).FindSubmatch(read(filepath.Join(root, "go.mod")))
	check(len(protobuf) == 2, "cannot determine GPUI protobuf version")
	h.module(app, "bao-gpui-headless", fmt.Sprintf("require github.com/moriyoshi/gpui-go v0.0.0\nrequire google.golang.org/protobuf %s\nreplace github.com/moriyoshi/gpui-go => %q\n", protobuf[1], root))
	args := []string{h.bao, "build", "-o", filepath.Join(app, "native")}
	for _, symbol := range []string{"gpui_go_init", "gpui_go_run_headless", "gpui_go_run_native", "gpui_go_stop", "sable_runtime_new", "sable_completion_efd", "sable_call_ctx", "sable_call_cancel", "sable_call_result", "sable_call_free", "sable_next_completion", "sable_runtime_shutdown", "sable_runtime_free"} {
		args = append(args, "-symbol", symbol)
	}
	h.run("gpui-producer.log", h.root, nil, append(args, archive)...)
	exe := filepath.Join(h.dst, "gpui-headless")
	h.consumer("gpui-build.log", app, h.goTool, "build", "-o", exe, ".")
	for _, procs := range []string{"1", "4"} {
		out := string(h.run("gpui-run-"+procs+".log", app, map[string]string{"GOMAXPROCS": procs}, exe))
		check(strings.Contains(out, "PASS: CGO_ENABLED=0 translated static archive"), "headless protocol failed")
	}
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-gpui-headless", false)
	h.saveJSON("gpui-alignment.json", alignment)
	h.run("gpui-sign.log", app, nil, "codesign", "--force", "--sign", "-", "--options", "runtime", exe)
	h.run("gpui-verify.log", app, nil, "codesign", "--verify", "--strict", exe)
	check(strings.Contains(string(h.consumer("gpui-signed-run.log", app, exe)), "PASS: CGO_ENABLED=0 translated static archive"), "signed GPUI run failed")
	check(digest(archive) == before, "GPUI input archive changed")
	h.results["gpui"] = map[string]any{"status": "PASS", "archive_sha256": before, "headless": "handshake, scene/events, cancellation, teardown; GOMAXPROCS=1/4", "signing": "ad-hoc Hardened Runtime and strict verify/rerun", "native_ui": "NOT VERIFIED", "background_tls": "remaining process/background blocks are not claimed to drain", "alignments_checked": len(alignment)}
}
