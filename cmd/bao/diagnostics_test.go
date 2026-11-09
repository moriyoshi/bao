package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moriyoshi/bao/linuxelf"
	"github.com/moriyoshi/bao/pecoff"
	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/translate"
)

func testSession(target string) (*diagnosticSession, *bytes.Buffer) {
	var out bytes.Buffer
	return newDiagnosticSession(diagnosticFlags{verbose: true}, "build", target, "input", &out), &out
}

func findingIDs(d *diagnosticSession) string {
	var ids []string
	for _, f := range d.report.Findings {
		ids = append(ids, f.ID+":"+f.Severity)
	}
	return strings.Join(ids, ",")
}

func TestSectionLimitFindings(t *testing.T) {
	for _, tc := range []struct {
		id    string
		limit int
	}{{findingELFSections, elfSectionLimit}, {findingMachOSections, machOSectionLimit}, {findingCOFFSections, coffSectionLimit}} {
		t.Run(tc.id, func(t *testing.T) {
			d, out := testSession("linux/arm64")
			d.limit(tc.id, "limits", "sections", tc.limit, tc.limit)
			if len(d.report.Findings) != 0 || !strings.Contains(out.String(), "headroom 0") {
				t.Fatalf("control at the limit: %s %s", findingIDs(d), out)
			}
			d, out = testSession("linux/arm64")
			d.limit(tc.id, "limits", "sections", tc.limit+1, tc.limit)
			if findingIDs(d) != tc.id+":FAIL" || !strings.Contains(out.String(), "limits FAIL sections") {
				t.Fatalf("over the limit: %s %s", findingIDs(d), out)
			}
		})
	}
	if got := commas(334676); got != "334,676" {
		t.Fatal(got)
	}
	if elfSectionLimit != 65279 {
		t.Fatal(elfSectionLimit)
	}
}

func densityFixture(count int) []textFunction {
	var out []textFunction
	for i := 0; i < count; i++ {
		out = append(out, textFunction{fmt.Sprintf("f%d", i), uint64(i), fmt.Sprintf("a:1:%d", i)})
	}
	return out
}

func TestFindfuncDensityFinding(t *testing.T) {
	d, _ := testSession("windows/amd64")
	d.checkDensity(densityFixture(findfuncBucketLimit))
	if len(d.report.Findings) != 0 {
		t.Fatalf("control: %s", findingIDs(d))
	}
	d, out := testSession("windows/amd64")
	d.checkDensity(densityFixture(findfuncBucketLimit + 12))
	if findingIDs(d) != findingFindfunc+":WARN" || !strings.Contains(out.String(), "functions WARN bucket density 268 / 256 predicted") || len(d.report.Findings[0].Evidence) != 268 {
		t.Fatalf("%s %s", findingIDs(d), out)
	}
}

func TestMachOOrdinalFinding(t *testing.T) {
	var libraries []string
	for i := 0; i < machOOrdinalLimit; i++ {
		libraries = append(libraries, fmt.Sprintf("/usr/lib/lib%d.dylib", i))
	}
	d, _ := testSession("darwin/arm64")
	d.checkOrdinals(libraries)
	if len(d.report.Findings) != 0 {
		t.Fatalf("control: %s", findingIDs(d))
	}
	d, _ = testSession("darwin/arm64")
	d.flags.assume = "net"
	d.checkOrdinals(libraries)
	if findingIDs(d) != findingOrdinal+":FAIL" || !strings.Contains(strings.Join(d.report.Findings[0].Evidence, "\n"), "net adds /usr/lib/libresolv.9.dylib") {
		t.Fatalf("%s %+v", findingIDs(d), d.report.Findings)
	}
	d, out := testSession("darwin/arm64")
	d.flags.assume = "unknown-package"
	d.checkOrdinals(libraries)
	if len(d.report.Findings) != 0 || !strings.Contains(out.String(), "assume-consumer SKIPPED") {
		t.Fatalf("unknown dependency must be named as skipped: %s", out)
	}
}

func TestBindDecoderFindsFlatNamespace(t *testing.T) {
	stream := []byte{0x11, 0x40}
	stream = append(stream, "_ok\x00"...)
	stream = append(stream, 0x90, 0x3e, 0x40)
	stream = append(stream, "_flat\x00"...)
	stream = append(stream, 0x90, 0x00)
	binds, err := decodeMachOBinds(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(binds) != 2 || binds[0] != (machOBind{"_ok", 1}) || binds[1] != (machOBind{"_flat", -2}) {
		t.Fatalf("%+v", binds)
	}
	if ordinalName(-2, nil) != "flat namespace" || ordinalName(0, nil) != "this image" || ordinalName(2, []string{"a", "b"}) != "b" || ordinalName(3, []string{"a"}) != "invalid ordinal" {
		t.Fatal("ordinal names")
	}
	if _, err := decodeMachOBinds([]byte{0x40, 'x'}); err == nil {
		t.Fatal("unterminated symbol accepted")
	}
}

func TestImportFindingsCoverEveryPlatform(t *testing.T) {
	for _, tc := range []struct {
		target string
		err    error
	}{
		{"windows/amd64", &pecoff.ImportError{Undefined: []string{"xkb_a", "xkb_b", "FT_a", "lonely"}}},
		{"linux/arm64", &linuxelf.UnresolvedError{Names: []string{"xkb_a", "xkb_b", "FT_a", "lonely"}}},
		{"darwin/amd64", &translate.UnresolvedError{Names: []string{"xkb_a", "xkb_b", "FT_a", "lonely"}}},
	} {
		d, out := testSession(tc.target)
		if got := d.finish(fmt.Errorf("wrapped: %w", tc.err), t.TempDir()); !errors.Is(got, tc.err) {
			t.Fatalf("%s: error changed: %v", tc.target, got)
		}
		text := out.String()
		for _, want := range []string{"imports FAIL 4 unresolved: xkb 2, other 2", "functions SKIPPED", "final-bind SKIPPED", "stopped: 1 failures; no package written"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s: %q missing from\n%s", tc.target, want, text)
			}
		}
		if findingIDs(d) != findingImportMissing+":FAIL" {
			t.Fatal(findingIDs(d))
		}
	}
	d, _ := testSession("linux/arm64")
	d.finish(errors.New("unrelated"), t.TempDir())
	if findingIDs(d) != findingGenerate+":FAIL" {
		t.Fatalf("control: %s", findingIDs(d))
	}
}

func TestDisabledDiagnosticsAreInert(t *testing.T) {
	var d *diagnosticSession
	want := errors.New("original")
	if got := d.finish(want, ""); got != want {
		t.Fatal(got)
	}
	if (diagnosticFlags{}).begin("build", toolchain.Target{Name: "linux/arm64"}, "missing", "", &bytes.Buffer{}) != nil {
		t.Fatal("session created without flags")
	}
}

func TestReportFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	d := newDiagnosticSession(diagnosticFlags{report: path}, "build", "linux/arm64", "input", &bytes.Buffer{})
	d.limit(findingELFSections, "limits", "sections", 70000, elfSectionLimit)
	d.skip("functions", "because")
	d.finish(nil, t.TempDir())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report diagnosticReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || len(report.Findings) != 1 || report.Findings[0].ID != findingELFSections || len(report.Skipped) == 0 || !strings.Contains(report.Note, "does not verify execution") {
		t.Fatalf("%+v", report)
	}
}

func TestTraceMatching(t *testing.T) {
	for _, tc := range []struct {
		symbol, name string
		ok           bool
	}{
		{"foo", "foo", true}, {"foo", "_foo", true}, {"_foo", "foo", true},
		{"foo", "bao_win_abc_foo", true}, {"foo", "myfoo", false}, {"foo", "x_foo", false},
	} {
		if traceMatches(tc.symbol, tc.name) != tc.ok {
			t.Fatalf("%+v", tc)
		}
	}
}

func TestManifestDarwinImportsUsesPublishedKeys(t *testing.T) {
	expected, err := manifestDarwinImports([]byte(`{"imports":[{"mach_o_symbol":"_a","go_symbol":"x","dynamic_symbol":"a","library":"/usr/lib/libSystem.B.dylib"},{"go_symbol":"y"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != 1 || expected["_a"] != "/usr/lib/libSystem.B.dylib" {
		t.Fatalf("%v", expected)
	}
}

func TestTraceTranslationInference(t *testing.T) {
	for _, tc := range []struct {
		symbol, before, after, want string
	}{
		{"section$end$__DATA$_X", "section$end$__DATA$_X: undefined", "section$end$__DATA$_X: defined", "inferred boundary synthesis"},
		{"_alias", "_alias: defined", "", "inferred alias folding"},
		{"cos", "cos: undefined", "cos: undefined", "system import"},
	} {
		d := newDiagnosticSession(diagnosticFlags{trace: symbolFlags{tc.symbol}}, "build", "darwin/amd64", "input", &bytes.Buffer{})
		d.tracePush(tc.symbol, "combined-object", []string{tc.before})
		if tc.after != "" {
			d.tracePush(tc.symbol, "generated-symbols", []string{tc.after})
		}
		d.traceTranslation()
		found := false
		for _, stage := range d.traces[tc.symbol].Stages {
			found = found || stage.Stage == "translation" && strings.Contains(stage.State[0], tc.want)
		}
		if !found {
			t.Fatalf("%s: %+v", tc.symbol, d.traces[tc.symbol])
		}
	}
}

func TestCappedAlignmentFinding(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "bao-manifest.json"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"imports":[]}`)
	d, out := testSession("windows/amd64")
	d.checkCappedAlignments(dir)
	if len(d.report.Findings) != 0 || !strings.Contains(out.String(), "alignment OK") {
		t.Fatalf("control: %s %s", findingIDs(d), out)
	}
	write(`{"windows_capped_alignments":[{"section":".rdata","Requested":64,"Applied":32}]}`)
	d, out = testSession("windows/amd64")
	d.checkCappedAlignments(dir)
	if findingIDs(d) != findingAlignCapped+":WARN" || !strings.Contains(out.String(), "alignment WARN 1 read-only") || d.report.Findings[0].Evidence[0] != ".rdata: requested 64, applied 32" {
		t.Fatalf("%s %s %+v", findingIDs(d), out, d.report.Findings)
	}
}
