package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Native Linux arm64 release checks must exercise the selected CLI artifact,
// including its embedded blobs, rather than silently recompiling a substitute.
// Other hosts still need a cross-built producer for the arm64 container.
func (h *harness) linuxProducer(log string) string {
	path := filepath.Join(h.dst, "bao-linux")
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" {
		copyFile(h.bao, path)
		require(os.Chmod(path, 0o755))
	} else {
		h.run(log, h.root, h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": "arm64"}), h.goTool, "build", "-o", path, "./cmd/bao")
	}
	h.results["linux_producer_sha256"] = digest(path)
	return path
}

func (h *harness) linux() {
	daemon := strings.TrimSpace(string(h.run("docker-info.log", h.root, nil, "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}")))
	check(daemon == "linux/aarch64" || daemon == "linux/arm64", "requires native arm64 Linux Docker daemon; got %s", daemon)
	h.linuxProducer("linux-bao-build.log")
	const compile = `set -eu
uname -m
rustc --version
gcc --version | head -1
ld --version | head -1
rustc --crate-type staticlib --crate-name bao_linux_runtime --edition=2024 -O /src/lib.rs -o /work/library.a
`
	output := string(h.run("linux-native-build.log", h.root, nil, "docker", "run", "--rm", "--platform", "linux/arm64", "--network", "none", "-v", filepath.Join(h.root, "examples/linux_runtime/src")+":/src:ro", "-v", h.dst+":/work", "--entrypoint", "/bin/sh", h.image, "-c", compile))
	check(strings.Contains(output, "aarch64") && strings.Contains(output, "rustc 1.99.1 "), "incorrect Linux Rust toolchain")
	app := filepath.Join(h.dst, "linux-consumer")
	h.module(app, "bao-linux-example", "")
	h.run("linux-producer.log", h.root, nil, "docker", "run", "--rm", "--platform", "linux/arm64", "--network", "none", "-v", h.dst+":/work", "--entrypoint", "/work/bao-linux", h.image, "build", "-target", "linux/arm64", "-sysroot", "/", "-symbol", "bao_example_run", "-symbol", "bao_example_check_finalized", "-o", "/work/linux-consumer/native", "/work/library.a")
	require(os.WriteFile(filepath.Join(app, "main.go"), []byte(`package main
import (
    "fmt"
    "runtime"
    "bao-linux-example/native"
    "github.com/ebitengine/purego"
)
func main() {
    runtime.LockOSThread()
    var run, check func() uint64
    purego.RegisterFunc(&run, native.SymbolAddr0())
    purego.RegisterFunc(&check, native.SymbolAddr1())
    if got := run(); got != 42 { panic(fmt.Sprintf("native result=%d", got)) }
    native.TLSFinalizeCurrentThread()
    if check()!=42 || native.TLSLiveBlocks()!=0 || native.TLSDestroyedBlocks()!=9 { panic("TLS destructor count") }
    fmt.Println("PASS: Linux arm64 panic/2 RAII drops/8 threads/9 TLS drops; constructors, libc callback, data, alignment; live=0 freed=9")
}
`), 0o644))
	exe := filepath.Join(h.dst, "linux-executable")
	cross := h.consumerEnv(map[string]string{"GOOS": "linux", "GOARCH": "arm64"})
	h.run("linux-consumer-build.log", app, cross, h.goTool, "build", "-o", exe, ".")
	info := string(h.run("linux-buildinfo.log", app, nil, h.goTool, "version", "-m", exe))
	check(strings.Contains(info, "CGO_ENABLED=0") && strings.Contains(info, puregoVersion) && !strings.Contains(info, "=>"), "consumer must use downloaded purego with cgo disabled")
	alignment := auditAlignment(filepath.Join(app, "native"), exe, "bao-linux-example", true)
	h.saveJSON("linux-alignment.json", alignment)
	execute := func(exe, log, procs string, negative bool) {
		out, err := h.command(log, h.root, nil, "docker", "run", "--rm", "--platform", "linux/arm64", "--network", "none", "--read-only", "-e", "GOMAXPROCS="+procs, "-e", "CC=/bao-no-cc", "-e", "RUSTC=/bao-no-rustc", "-v", h.dst+":/work:ro", "--entrypoint", "/work/"+filepath.Base(exe), h.image)
		if negative {
			check(err != nil && strings.Contains(string(out), "failed to initiate panic") && !strings.Contains(string(out), "PASS:"), "Linux unwind negative control did not fail as expected")
		} else {
			require(err)
			check(strings.Contains(string(out), "PASS: Linux arm64"), "Linux runtime did not pass")
		}
	}
	for _, procs := range []string{"1", "4"} {
		execute(exe, "linux-run-"+procs+".log", procs, false)
	}
	negative := filepath.Join(h.dst, "linux-negative")
	copyTree(app, negative)
	path := filepath.Join(negative, "native/symbols_linux_arm64.go")
	source := string(read(path))
	check(strings.Contains(source, "registerFrame(unwindAddress"), "no Linux FDE registration to disable")
	require(os.WriteFile(path, []byte(strings.ReplaceAll(source, "registerFrame(unwindAddress", "func(uintptr) {}(unwindAddress")), 0o644))
	negexe := filepath.Join(h.dst, "linux-negative-executable")
	h.run("linux-negative-link.log", negative, cross, h.goTool, "build", "-o", negexe, ".")
	execute(negexe, "linux-negative-run.log", "1", true)
	manifest := readJSON(filepath.Join(app, "native/bao-manifest.json"))
	h.results["linux"] = map[string]any{"status": "PASS", "daemon": daemon, "image": h.image, "execution": "native Linux arm64, read-only/no-network, GOMAXPROCS=1/4", "producer": "bao build from Rust archive using native GNU ld", "tls_descriptors": manifest["tls_descriptors"], "alignments_checked": len(alignment), "runtime": "panic caught, 2 RAII drops, 8 threads, 9 TLS destructors, live=0 freed=9", "negative_unwind": "PASS", "executable_sha256": digest(exe)}
	fmt.Println("PASS Linux arm64")
}
