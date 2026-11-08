package bindings

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestScalarABIAllocation(t *testing.T) {
	win, space, err := layout("windows/amd64", []string{"int64", "float64", "int64", "float32", "int8", "float64"})
	if err != nil || win[0].reg != "CX" || win[1].reg != "X1" || win[2].reg != "R8" || win[3].reg != "X3" || win[4].reg != "" || win[4].offset != 32 || win[5].offset != 40 || space != 48 {
		t.Fatalf("Win64 ordinal slots and shadow space: %+v %d %v", win, space, err)
	}
	win, space, err = layout("windows/arm64", []string{"int64", "float64", "int64", "float32"})
	if err != nil || win[0].reg != "R0" || win[1].reg != "F0" || win[2].reg != "R1" || win[3].reg != "F1" || space != 0 {
		t.Fatalf("Windows ARM64 fixed scalar register banks: %+v %d %v", win, space, err)
	}
	amd, spill, err := layout("linux/amd64", []string{"int8", "float64", "int64", "int64", "int64", "int64", "int64", "int16", "float32"})
	if err != nil || amd[0].reg != "DI" || amd[1].reg != "X0" || amd[6].reg != "R9" || amd[7].reg != "" || amd[7].offset != 0 || amd[8].reg != "X1" || spill != 8 {
		t.Fatalf("SysV amd64 allocation: %+v %d %v", amd, spill, err)
	}
	params := []string{"int64", "int64", "int64", "int64", "int64", "int64", "int64", "int64", "int8", "int16", "int32"}
	l, _, err := layout("darwin/arm64", params)
	if err != nil {
		t.Fatal(err)
	}
	if l[8].offset != 0 || l[9].offset != 2 || l[10].offset != 4 {
		t.Fatal("Darwin narrow stack arguments must retain natural packing")
	}
	l, _, err = layout("linux/arm64", params)
	if err != nil {
		t.Fatal(err)
	}
	if l[8].offset != 0 || l[9].offset != 8 || l[10].offset != 16 {
		t.Fatal("AAPCS64 stack slots must be eight bytes")
	}
	l, _, err = layout("linux/loong64", []string{"float32", "float32", "float32", "float32", "float32", "float32", "float32", "float32", "float32", "int32"})
	if err != nil {
		t.Fatal(err)
	}
	if l[8].reg != "R4" || l[9].reg != "R5" {
		t.Fatal("LoongArch exhausted FARs must fall back to GARs")
	}
	l, _, err = layout("linux/ppc64le", []string{"float32", "int64", "float64", "int64"})
	if err != nil {
		t.Fatal(err)
	}
	if l[0].reg != "F1" || l[1].reg != "R4" || l[2].reg != "F2" || l[3].reg != "R6" {
		t.Fatal("ELFv2 floating arguments must consume general parameter positions")
	}
}

func TestBundledBootstrapSourceProvenance(t *testing.T) {
	b, err := bootstrap.ReadFile("bootstrap/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Files map[string]string `json:"files"`
	}
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	for name, want := range p.Files {
		path := "bootstrap/" + name
		if name != "LICENSE-GO.txt" && name != "LICENSE-PUREGO.txt" {
			path += ".txt"
		}
		b, err := bootstrap.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatalf("upstream bootstrap changed: %s", name)
		}
	}
}
