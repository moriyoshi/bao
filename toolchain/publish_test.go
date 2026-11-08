package toolchain

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishPreservesExistingDirectoriesAndCleansFailedReservation(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	output := filepath.Join(dir, "native")
	os.Mkdir(stage, 0o755)
	os.WriteFile(filepath.Join(stage, "artifact"), []byte("completed"), 0o644)
	os.Mkdir(output, 0o755)
	if err := Publish(stage, output); err == nil {
		t.Fatal("overwrote an existing empty directory")
	}
	os.WriteFile(filepath.Join(output, "user"), []byte("preserve"), 0o644)
	if err := Publish(stage, output); err == nil {
		t.Fatal("overwrote user files")
	}
	os.Remove(filepath.Join(output, "user"))
	os.Remove(output)
	if err := Publish(stage, output); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(output, "artifact")); err != nil || string(b) != "completed" {
		t.Fatalf("published package incomplete: %s %v", b, err)
	}
	failed := filepath.Join(dir, "failed")
	if err := Publish(filepath.Join(dir, "missing"), failed); err == nil {
		t.Fatal("missing package published")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("failed publication left an output directory")
	}
}

func TestPublishRacingProducersPreserveWinner(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "native")
	start := make(chan struct{})
	type result struct {
		index int
		err   error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		stage := filepath.Join(dir, fmt.Sprintf("stage-%d", i))
		if err := os.Mkdir(stage, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage, "artifact"), []byte(fmt.Sprint(i)), 0644); err != nil {
			t.Fatal(err)
		}
		go func(i int, stage string) { <-start; results <- result{i, Publish(stage, output)} }(i, stage)
	}
	close(start)
	winner, loser := -1, -1
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil {
			if winner != -1 {
				t.Fatal("both producers published")
			}
			winner = r.index
		} else {
			loser = r.index
		}
	}
	if winner < 0 || loser < 0 {
		t.Fatal("publication did not choose exactly one producer")
	}
	if data, err := os.ReadFile(filepath.Join(output, "artifact")); err != nil || string(data) != fmt.Sprint(winner) {
		t.Fatalf("winner was replaced: %s %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("stage-%d", loser), "artifact")); err != nil || string(data) != fmt.Sprint(loser) {
		t.Fatalf("losing producer's stage was lost: %s %v", data, err)
	}
}

func TestPublishPreservesExistingFileAndRejectsFileSource(t *testing.T) {
	dir := t.TempDir()
	stage, output := filepath.Join(dir, "stage"), filepath.Join(dir, "native")
	if err := os.Mkdir(stage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("user file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Publish(stage, output); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if b, err := os.ReadFile(output); err != nil || string(b) != "user file" {
		t.Fatalf("existing file changed: %s %v", b, err)
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("failed publication removed stage", err)
	}
	missing := filepath.Join(dir, "new-output")
	if err := Publish(output, missing); err == nil {
		t.Fatal("published a file as a package directory")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("invalid publication left output", err)
	}
}
