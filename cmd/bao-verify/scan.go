package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	auth "github.com/moriyoshi/bao/verify"
)

// downloadedScan exercises a real module cache without contacting a network
// proxy. A local file proxy is available only during explicit fixture setup.
func (h *harness) downloadedScan(dir, module, policy, envelope string) {
	fixture := filepath.Join(dir, "scan")
	proxy, cache, app := filepath.Join(fixture, "proxy"), filepath.Join(fixture, "cache"), filepath.Join(fixture, "app")
	require(os.MkdirAll(app, 0700))
	const native = "bao.test/signed-native"
	const unsigned = "bao.test/unused-native"
	const missing = "bao.test/not-downloaded"
	files, err := auth.Tree(module, "")
	require(err)
	nativeFiles := map[string][]byte{}
	for _, file := range files {
		nativeFiles[file.Path] = read(filepath.Join(module, file.Path))
	}
	for path, contents := range map[string]map[string][]byte{
		native:   nativeFiles,
		unsigned: {"go.mod": []byte("module " + unsigned + "\ngo 1.26.0\n"), "init.go": []byte("package unused;func init(){panic(\"must not execute\")}\n"), "unused_other.syso": []byte("unsigned native payload")},
		missing:  {"go.mod": []byte("module " + missing + "\ngo 1.26.0\n")},
	} {
		versionDir := filepath.Join(proxy, path, "@v")
		require(os.MkdirAll(versionDir, 0700))
		require(os.WriteFile(filepath.Join(versionDir, "v1.0.0.mod"), contents["go.mod"], 0600))
		require(os.WriteFile(filepath.Join(versionDir, "v1.0.0.info"), []byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`), 0600))
		require(os.WriteFile(filepath.Join(versionDir, "list"), []byte("v1.0.0\n"), 0600))
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		for name, data := range contents {
			entry, err := writer.Create(path + "@v1.0.0/" + name)
			require(err)
			_, err = entry.Write(data)
			require(err)
		}
		require(writer.Close())
		require(os.WriteFile(filepath.Join(versionDir, "v1.0.0.zip"), buf.Bytes(), 0600))
	}
	require(os.WriteFile(filepath.Join(app, "go.mod"), []byte(fmt.Sprintf("module scan-consumer\ngo 1.26.0\nrequire (\n%s v1.0.0\n%s v1.0.0\n%s v1.0.0\n)\n", native, unsigned, missing)), 0600))
	// There is intentionally no compilable application and no import of the
	// unsigned dependency. The scan must still find its downloaded .syso.
	setup := map[string]string{"GOPROXY": "file://" + filepath.ToSlash(proxy), "GOSUMDB": "off", "GOMODCACHE": cache}
	h.run("scan-setup-metadata.log", app, setup, h.goTool, "list", "-m", "-mod=mod", "all")
	h.run("scan-setup-download.log", app, setup, h.goTool, "mod", "download", native+"@v1.0.0", unsigned+"@v1.0.0")
	require(os.Rename(proxy, proxy+"-unavailable")) // Even accidental fetching cannot succeed.
	scan := func(name, rejection string) auth.ScanReport {
		wantOK := rejection == ""
		out, err := h.command("scan-"+name+".log", app, map[string]string{"GOMODCACHE": cache, "GOFLAGS": "-toolexec=/must-not-execute"}, h.bao, "verify", "-go", h.goTool, "-target", "darwin/arm64", "-policy", policy, "-manifest", envelope, "-json")
		check((err == nil) == wantOK, "scan %s: %v: %s", name, err, out)
		if !wantOK {
			check(strings.Contains(string(out), rejection), "scan %s failed for the wrong reason: %s", name, out)
		}
		// command combines stderr and stdout; successful reports have no stderr.
		var report auth.ScanReport
		if wantOK {
			require(json.Unmarshal(out, &report))
		}
		return report
	}
	scan("unsigned-unused-dependency", "native dependency bao.test/unused-native requires")
	h.run("scan-drop-unsigned.log", app, map[string]string{"GOMODCACHE": cache}, h.goTool, "mod", "edit", "-droprequire="+unsigned)
	report := scan("approved-downloaded-dependency", "")
	check(report.MainModule == "scan-consumer" && len(report.Authenticated) == 1 && report.NativeFiles != 0, "incomplete downloaded scan: %+v", report)
	notDownloaded := false
	for _, m := range report.Modules {
		notDownloaded = notDownloaded || m.Path == missing && m.Status == "not-downloaded"
	}
	check(notDownloaded, "missing sources not explicitly reported: %+v", report)
	for _, file := range files {
		if strings.HasSuffix(file.Path, ".syso") {
			path := filepath.Join(cache, native+"@v1.0.0", file.Path)
			b := read(path)
			b[len(b)-1] ^= 1
			require(os.Chmod(path, 0600))
			require(os.WriteFile(path, b, 0600))
			break
		}
	}
	scan("modified-module-cache", "offline go mod verify")
	h.results["downloaded_dependency_scan"] = "PASS: actual offline Go module cache; approved source; unused unsigned native dependency rejected; missing download reported; modified cache rejected; no application compiled or run"
}
