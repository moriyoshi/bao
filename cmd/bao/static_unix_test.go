//go:build !windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFailedNativeLinkDoesNotPublishOrLeaveScratch(t *testing.T) {
	dir := t.TempDir()
	// Structural arm64 Mach-O archive and a Unix shell linker failure fixture.
	object := make([]byte, 32)
	binary.LittleEndian.PutUint32(object, 0xfeedfacf)
	binary.LittleEndian.PutUint32(object[4:], 0x100000c)
	binary.LittleEndian.PutUint32(object[12:], 1)
	archive := filepath.Join(dir, "input with spaces.a")
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", "leaf.o/", 0, 0, 0, "644", len(object))
	os.WriteFile(archive, append([]byte("!<arch>\n"+header), object...), 0o644)
	sdk := filepath.Join(dir, "sdk")
	os.Mkdir(sdk, 0o755)
	os.WriteFile(filepath.Join(sdk, "SDKSettings.json"), []byte(`{"Version":"26.5"}`), 0o644)
	linker := filepath.Join(dir, "failing linker")
	os.WriteFile(linker, []byte("#!/bin/sh\necho intentional-link-failure >&2\nexit 7\n"), 0o755)
	output := filepath.Join(dir, "native")
	var stdout, stderr strings.Builder
	err := run([]string{"build", "-target", "darwin/arm64", "-sdk", sdk, "-ld", linker, "-o", output, archive}, &stdout, &stderr)
	if err == nil || !strings.Contains(stderr.String(), "intentional-link-failure") {
		t.Fatalf("link failure lost: %v %s", err, stderr.String())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed build published output")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".bao-build-*"))
	if len(matches) != 0 {
		t.Fatalf("scratch retained after failure: %v", matches)
	}
}

// A FIFO notice provides a deterministic barrier after native input snapshots
// but before archive combination. No compiler, SDK, watcher race or subprocess
// is needed to prove that replacing caller-owned files cannot change the
// native instructions or the provenance of this producer invocation.
func TestBuildUsesCapturedInputsWhenOriginalsChange(t *testing.T) {
	dir := t.TempDir()
	primary, dep := filepath.Join(dir, "primary.a"), filepath.Join(dir, "dependency.a")
	primaryBytes := writeStaticArchive(t, primary, "answer")
	depBytes := writeStaticArchive(t, dep, "unused")
	noticeBytes := []byte("Original runtime notice\n")
	notice := filepath.Join(dir, "notice")
	if err := os.WriteFile(notice, noticeBytes, 0644); err != nil {
		t.Fatal(err)
	}
	build := func(output string) error {
		var stdout, stderr strings.Builder
		return run([]string{"build", "-target", "windows/amd64", "-symbol", "answer", "-link-archive", dep, "-link-notice", notice, "-o", output, primary}, &stdout, &stderr)
	}
	baseline := filepath.Join(dir, "baseline")
	if err := build(baseline); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(notice); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(notice, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "snapshot")
	done := make(chan error, 1)
	go func() { done <- build(output) }()
	var writer *os.File
	deadline := time.Now().Add(5 * time.Second)
	for writer == nil {
		fd, err := syscall.Open(notice, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			writer = os.NewFile(uintptr(fd), notice)
			break
		}
		if err != syscall.ENXIO {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			t.Fatalf("build finished before snapshot barrier: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("producer did not reach snapshot barrier")
		}
		time.Sleep(time.Millisecond)
	}
	defer writer.Close()
	// The producer is reading the FIFO; its primary/archive snapshots already
	// exist. Malformed replacement bytes would make target detection fail if it
	// read either original again for translation.
	for _, path := range []string{primary, dep} {
		if err := os.WriteFile(path, []byte("replaced after capture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Write(noticeBytes); err != nil {
		t.Fatal(err)
	}
	// Replacing the pathname leaves the producer's open pipe intact while the
	// caller-owned notice now contains different bytes for any later reread.
	if err := os.Remove(notice); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notice, []byte("replaced notice"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot build did not finish")
	}
	var provenance struct {
		SourceSHA256   string                              `json:"source_sha256"`
		LinkedArchives []struct{ SHA256 string }           `json:"linked_archives"`
		LinkedNotices  []struct{ SHA256, Artifact string } `json:"linked_notices"`
	}
	data, err := os.ReadFile(filepath.Join(output, "bao-build.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.SourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(primaryBytes)) || len(provenance.LinkedArchives) != 1 || provenance.LinkedArchives[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256(depBytes)) || len(provenance.LinkedNotices) != 1 || provenance.LinkedNotices[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256(noticeBytes)) {
		t.Fatalf("provenance described replaced originals: %+v", provenance)
	}
	retained, err := os.ReadFile(filepath.Join(output, provenance.LinkedNotices[0].Artifact))
	if err != nil || !bytes.Equal(retained, noticeBytes) {
		t.Fatalf("retained notice changed: %q %v", retained, err)
	}
	entries, err := os.ReadDir(baseline)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if ext != ".go" && ext != ".s" && ext != ".syso" {
			continue
		}
		before, err := os.ReadFile(filepath.Join(baseline, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Join(output, entry.Name()))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("replaced original changed generated artifact %s: %v", entry.Name(), err)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("did not compare generated Go/assembly/native instructions: %d", checked)
	}
}
