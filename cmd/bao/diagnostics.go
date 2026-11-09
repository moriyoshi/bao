package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/moriyoshi/bao/internal/ar"
	"github.com/moriyoshi/bao/linuxelf"
	"github.com/moriyoshi/bao/pecoff"
	"github.com/moriyoshi/bao/toolchain"
	"github.com/moriyoshi/bao/translate"
)

// Stable finding IDs. Consumers of -report match on these, not message text.
const (
	findingELFSections   = "BAO-ELF-SECTIONS"
	findingMachOSections = "BAO-MACHO-SECTIONS"
	findingCOFFSections  = "BAO-COFF-SECTIONS"
	findingFindfunc      = "BAO-GO-FINDFUNC"
	findingOrdinal       = "BAO-MACHO-ORDINAL"
	findingFlatBind      = "BAO-MACHO-FLAT-BIND"
	findingImportMissing = "BAO-IMPORT-MISSING"
	findingGenerate      = "BAO-GENERATE"
	findingAlignCapped   = "BAO-COFF-ALIGNMENT-CAPPED"
)

const (
	elfSectionLimit   = int(elf.SHN_LORESERVE) - 1
	machOSectionLimit = 255
	coffSectionLimit  = 0xffff
	// Go stores a one-byte delta per 4 KiB findfunc bucket.
	findfuncBucketLimit = 256
	// cmd/link 1.26.10 masks SET_DYLIB_ORDINAL_IMM with 0xf.
	machOOrdinalLimit = 15
)

// consumerLibraries lists dylibs a common consumer dependency adds on Darwin.
var consumerLibraries = map[string][]string{
	"net":         {"/usr/lib/libresolv.9.dylib"},
	"crypto/x509": {"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Security.framework/Versions/A/Security"},
}

type diagnosticFlags struct {
	verbose, evidence bool
	report, assume    string
	trace             symbolFlags
}

func (f *diagnosticFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.verbose, "v", false, "collect every error in a stage; print one line per stage with limits and headroom to stderr")
	fs.BoolVar(&f.evidence, "vv", false, "like -v, plus the symbols, alias groups and relocations behind each number")
	fs.Var(&f.trace, "trace", "print SYMBOL's state at each stage; repeatable")
	fs.StringVar(&f.report, "report", "", "write findings as JSON to this file")
	fs.StringVar(&f.assume, "assume-consumer", "", "comma-separated consumer dependencies counted in limits, such as net,crypto/x509")
}

func (f *diagnosticFlags) enabled() bool {
	return f.verbose || f.evidence || f.report != "" || len(f.trace) != 0
}

type diagnosticStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Value  *int   `json:"value,omitempty"`
	Limit  *int   `json:"limit,omitempty"`
}

type diagnosticFinding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Stage    string   `json:"stage"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

type diagnosticSkip struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

type diagnosticTraceStage struct {
	Stage string   `json:"stage"`
	State []string `json:"state"`
}

type diagnosticTrace struct {
	Symbol string                 `json:"symbol"`
	Stages []diagnosticTraceStage `json:"stages"`
}

type diagnosticReport struct {
	SchemaVersion int                 `json:"schema_version"`
	Command       string              `json:"command"`
	Target        string              `json:"target"`
	Input         string              `json:"input"`
	Result        string              `json:"result"`
	Note          string              `json:"note"`
	Stages        []diagnosticStage   `json:"stages"`
	Findings      []diagnosticFinding `json:"findings"`
	Skipped       []diagnosticSkip    `json:"skipped"`
	Traces        []diagnosticTrace   `json:"traces,omitempty"`
}

type diagnosticSession struct {
	flags   diagnosticFlags
	out     io.Writer
	target  toolchain.Target
	input   string
	sysroot string
	report  diagnosticReport
	source  string
	traces  map[string]*diagnosticTrace
}

func newDiagnosticSession(flags diagnosticFlags, command, target, input string, out io.Writer) *diagnosticSession {
	d := &diagnosticSession{flags: flags, out: out, input: input, traces: map[string]*diagnosticTrace{}}
	d.target.Name = target
	d.report = diagnosticReport{SchemaVersion: 1, Command: command, Target: target, Input: input, Note: "A clean report means no known limit was exceeded; it does not verify execution."}
	for _, symbol := range flags.trace {
		d.traces[symbol] = &diagnosticTrace{Symbol: symbol}
	}
	return d
}

func (f diagnosticFlags) begin(command string, target toolchain.Target, input, source string, out io.Writer) *diagnosticSession {
	if !f.enabled() {
		return nil
	}
	if command == "" {
		command = "build"
	}
	d := newDiagnosticSession(f, command, target.Name, input, out)
	d.target = target
	d.source = source
	d.analyzeInput(input)
	return d
}

func (d *diagnosticSession) printing() bool { return d.flags.verbose || d.flags.evidence }

func (d *diagnosticSession) stage(name, status, detail string, value, limit *int) {
	d.report.Stages = append(d.report.Stages, diagnosticStage{name, status, detail, value, limit})
	if d.printing() {
		fmt.Fprintf(d.out, "%s %s %s\n", name, status, detail)
	}
}

func (d *diagnosticSession) finding(id, severity, stage, message string, evidence ...string) {
	d.report.Findings = append(d.report.Findings, diagnosticFinding{id, severity, stage, message, evidence})
	if d.flags.evidence {
		for _, line := range evidence {
			fmt.Fprintf(d.out, "  %s: %s\n", id, line)
		}
	}
}

func (d *diagnosticSession) skip(stage, reason string) {
	d.report.Skipped = append(d.report.Skipped, diagnosticSkip{stage, reason})
	if d.printing() {
		fmt.Fprintf(d.out, "%s SKIPPED %s\n", stage, reason)
	}
}

func commas(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func (d *diagnosticSession) limit(id, stage, label string, value, limit int) {
	status := "OK"
	if value > limit {
		status = "FAIL"
	}
	detail := fmt.Sprintf("%s %s / %s", label, commas(value), commas(limit))
	if value <= limit {
		detail += fmt.Sprintf(" (headroom %s)", commas(limit-value))
	}
	v, l := value, limit
	d.stage(stage, status, detail, &v, &l)
	if status == "FAIL" {
		d.finding(id, "FAIL", stage, detail)
	}
}

func (d *diagnosticSession) analyzeInput(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		d.skip("limits", "input unreadable: "+err.Error())
		return
	}
	if d.source != "" && d.source != path {
		if original, err := os.ReadFile(d.source); err == nil {
			d.traceStage("archive", original)
		}
		d.traceStage("combined-object", data)
	} else if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		d.traceStage("archive", data)
	} else {
		d.traceStage("combined-object", data)
	}
	if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		members, err := ar.Parse(data)
		if err != nil {
			d.skip("limits", "archive unreadable: "+err.Error())
			return
		}
		most := 0
		for _, m := range members {
			if f, err := pe.NewFile(bytes.NewReader(m.Data)); err == nil {
				most = max(most, len(f.Sections))
			}
		}
		if strings.HasPrefix(d.target.Name, "windows/") {
			d.limit(findingCOFFSections, "limits", "sections (largest member)", most, coffSectionLimit)
			return
		}
		d.skip("limits", "archive inputs are checked after combining")
		return
	}
	d.limitsForObject(data)
}

func (d *diagnosticSession) limitsForObject(data []byte) {
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		d.limit(findingELFSections, "limits", "sections", len(f.Sections), elfSectionLimit)
		return
	}
	if f, err := macho.NewFile(bytes.NewReader(data)); err == nil {
		d.limit(findingMachOSections, "limits", "sections", len(f.Sections), machOSectionLimit)
		return
	}
	if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
		d.limit(findingCOFFSections, "limits", "sections", len(f.Sections), coffSectionLimit)
		return
	}
	d.skip("limits", "unrecognized object format")
}

// finish records generation's outcome and returns err unchanged.
func (d *diagnosticSession) finish(err error, output string) error {
	if d == nil {
		return err
	}
	if err != nil {
		d.classify(err)
		d.skip("functions", "generation failed; no objects to measure")
		d.skip("libraries", "generation failed; no package to read")
		d.skip("ordinals", "generation failed; no package to read")
		d.skip("generated-symbols", "generation failed; no objects to read")
		d.skip("final-bind", "generation failed; no executable exists")
		for _, t := range d.flags.trace {
			d.tracePush(t, "generated-symbols", []string{"skipped: generation failed"})
		}
	} else {
		d.analyzeOutput(output)
		d.skip("final-bind", "no executable at this stage; run inspect -v -manifest bao-manifest.json on the built program")
	}
	failures := 0
	for _, f := range d.report.Findings {
		if f.Severity == "FAIL" {
			failures++
		}
	}
	switch {
	case err != nil:
		d.report.Result = fmt.Sprintf("stopped: %d failures; no package written", max(failures, 1))
	case failures != 0:
		d.report.Result = fmt.Sprintf("finished: %d predicted failures; package written", failures)
	case len(d.report.Findings) != 0:
		d.report.Result = fmt.Sprintf("finished: %d warnings; package written; execution not verified", len(d.report.Findings))
	default:
		d.report.Result = "finished: no known limit exceeded; package written; execution not verified"
	}
	if d.printing() {
		fmt.Fprintln(d.out, d.report.Result)
	}
	d.close()
	return err
}

func (d *diagnosticSession) close() {
	d.report.Traces = nil
	for _, symbol := range d.flags.trace {
		trace := d.traces[symbol]
		d.report.Traces = append(d.report.Traces, *trace)
		fmt.Fprintf(d.out, "trace %s\n", symbol)
		for _, stage := range trace.Stages {
			for _, line := range stage.State {
				fmt.Fprintf(d.out, "  %-18s %s\n", stage.Stage, line)
			}
		}
	}
	if d.flags.report == "" {
		return
	}
	buf, err := json.MarshalIndent(d.report, "", "  ")
	if err == nil {
		err = os.WriteFile(d.flags.report, append(buf, '\n'), 0644)
	}
	if err != nil {
		fmt.Fprintf(d.out, "report not written: %v\n", err)
	}
}

// classify turns collected translator errors into findings grouped by kind.
func (d *diagnosticSession) classify(err error) {
	var names, bare []string
	var windows *pecoff.ImportError
	var linux *linuxelf.UnresolvedError
	var darwin *translate.UnresolvedError
	switch {
	case errors.As(err, &windows):
		names, bare = windows.Undefined, windows.Bare
	case errors.As(err, &linux):
		names = linux.Names
	case errors.As(err, &darwin):
		names = darwin.Names
	default:
		d.stage("generate", "FAIL", err.Error(), nil, nil)
		d.finding(findingGenerate, "FAIL", "generate", err.Error())
		return
	}
	all := append(append([]string{}, names...), bare...)
	detail := fmt.Sprintf("%d unresolved: %s", len(all), groupedNames(all))
	v := len(all)
	d.stage("imports", "FAIL", detail, &v, nil)
	evidence := append([]string{}, all...)
	if strings.HasPrefix(d.target.Name, "linux/") {
		evidence = append(evidence, d.suggestLinuxLibraries(names)...)
	}
	d.finding(findingImportMissing, "FAIL", "imports", detail, evidence...)
}

var namePrefix = regexp.MustCompile(`^_*([A-Za-z0-9]+?)(_|[A-Z][a-z]|$)`)

func groupedNames(names []string) string {
	counts := map[string]int{}
	for _, name := range names {
		key := "other"
		if m := namePrefix.FindStringSubmatch(name); m != nil {
			key = m[1]
		}
		counts[key]++
	}
	other := 0
	type group struct {
		name  string
		count int
	}
	var groups []group
	for name, count := range counts {
		if name == "other" || count < 2 {
			other += count
			continue
		}
		groups = append(groups, group{name, count})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].count != groups[j].count {
			return groups[i].count > groups[j].count
		}
		return groups[i].name < groups[j].name
	})
	var parts []string
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("%s %d", g.name, g.count))
	}
	if other != 0 {
		parts = append(parts, fmt.Sprintf("other %d", other))
	}
	return strings.Join(parts, ", ")
}

// suggestLinuxLibraries reports which sysroot libraries export the missing names.
// It is advice only: binding still requires an explicit -linux-system-library.
func (d *diagnosticSession) suggestLinuxLibraries(names []string) []string {
	if d.sysroot == "" {
		return nil
	}
	exporters, err := linuxelf.Exporters(d.sysroot, strings.TrimPrefix(d.target.Name, "linux/"), names)
	if err != nil {
		d.skip("library-search", err.Error())
		return nil
	}
	found := map[string]int{}
	unknown := 0
	for _, name := range names {
		if libs := exporters[name]; len(libs) != 0 {
			found[libs[0]]++
		} else {
			unknown++
		}
	}
	var libs []string
	for lib := range found {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	var lines []string
	for _, lib := range libs {
		lines = append(lines, fmt.Sprintf("-linux-system-library %s would satisfy %d", lib, found[lib]))
		if d.printing() {
			fmt.Fprintf(d.out, "imports HINT -linux-system-library %s would satisfy %d\n", lib, found[lib])
		}
	}
	if unknown != 0 {
		lines = append(lines, fmt.Sprintf("%d names have no exporter in the sysroot", unknown))
	}
	return lines
}

type textFunction struct {
	name    string
	address uint64
	key     string
}

func sysoFiles(output string) []string {
	files, _ := filepath.Glob(filepath.Join(output, "*.syso"))
	sort.Strings(files)
	return files
}

func (d *diagnosticSession) analyzeOutput(output string) {
	files := sysoFiles(output)
	var functions []textFunction
	base := uint64(0)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			d.skip("functions", err.Error())
			return
		}
		more, size := objectFunctions(data, filepath.Base(path), base)
		functions = append(functions, more...)
		base += size
		d.traceStage("generated-symbols", data)
		d.traceRelocations(data, filepath.Base(path))
	}
	d.traceTranslation()
	d.checkDensity(functions)
	d.checkCappedAlignments(output)
	libraries := generatedLibraries(output)
	if len(libraries) == 0 {
		d.skip("libraries", "package records no system libraries")
	} else {
		d.stage("libraries", "OK", fmt.Sprintf("%d: %s", len(libraries), strings.Join(libraries, ", ")), nil, nil)
	}
	if strings.HasPrefix(d.target.Name, "darwin/") {
		d.checkOrdinals(libraries)
	}
}

func objectFunctions(data []byte, file string, base uint64) ([]textFunction, uint64) {
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		symbols, _ := f.Symbols()
		offsets := map[int]uint64{}
		cursor := uint64(0)
		for i, s := range f.Sections {
			if s.Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}
			align := max(s.Addralign, 1)
			cursor = (cursor + align - 1) &^ (align - 1)
			offsets[i] = cursor
			cursor += s.Size
		}
		var out []textFunction
		for _, s := range symbols {
			at, ok := offsets[int(s.Section)]
			kind := elf.ST_TYPE(s.Info)
			if !ok || (kind != elf.STT_FUNC && kind != elf.STT_NOTYPE) {
				continue
			}
			out = append(out, textFunction{s.Name, base + at + s.Value, fmt.Sprintf("%s:%d:%d", file, s.Section, s.Value)})
		}
		return out, cursor
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, 0
	}
	offsets := map[int]uint64{}
	cursor := uint64(0)
	for i, s := range f.Sections {
		if s.Characteristics&pe.IMAGE_SCN_CNT_CODE == 0 {
			continue
		}
		align := uint64(1)
		if a := s.Characteristics >> 20 & 15; a > 0 {
			align = 1 << (a - 1)
		}
		cursor = (cursor + align - 1) &^ (align - 1)
		offsets[i+1] = cursor
		cursor += uint64(s.Size)
	}
	var out []textFunction
	for i := 0; i < len(f.COFFSymbols); {
		s := f.COFFSymbols[i]
		i += 1 + int(s.NumberOfAuxSymbols)
		at, ok := offsets[int(s.SectionNumber)]
		name, _ := s.FullName(f.StringTable)
		if !ok || s.StorageClass == 3 && strings.HasPrefix(name, ".") {
			continue
		}
		out = append(out, textFunction{name, base + at + uint64(s.Value), fmt.Sprintf("%s:%d:%d", file, s.SectionNumber, s.Value)})
	}
	return out, cursor
}

func (d *diagnosticSession) checkDensity(functions []textFunction) {
	if len(functions) == 0 {
		d.skip("functions", "no native text symbols")
		return
	}
	buckets := map[uint64][]textFunction{}
	groups := map[string][]string{}
	for _, f := range functions {
		buckets[f.address>>12] = append(buckets[f.address>>12], f)
		groups[f.key] = append(groups[f.key], f.name)
	}
	var densest uint64
	most := -1
	for bucket, items := range buckets {
		if len(items) > most || len(items) == most && bucket < densest {
			densest, most = bucket, len(items)
		}
	}
	largest := 0
	for _, names := range groups {
		largest = max(largest, len(names))
	}
	status := "OK"
	if most > findfuncBucketLimit {
		status = "WARN"
	}
	detail := fmt.Sprintf("bucket density %d / %d predicted, %d aliases at one address", most, findfuncBucketLimit, largest)
	v, l := most, findfuncBucketLimit
	d.stage("functions", status, detail, &v, &l)
	if status == "WARN" {
		var evidence []string
		for _, f := range buckets[densest] {
			evidence = append(evidence, f.name)
		}
		sort.Strings(evidence)
		d.finding(findingFindfunc, "WARN", "functions", detail, evidence...)
	}
}

// checkCappedAlignments keeps an opted-in alignment cap visible in every report.
func (d *diagnosticSession) checkCappedAlignments(output string) {
	if !strings.HasPrefix(d.target.Name, "windows/") {
		return
	}
	data, err := os.ReadFile(filepath.Join(output, "bao-manifest.json"))
	if err != nil {
		d.skip("alignment", err.Error())
		return
	}
	var parsed struct {
		Capped []pecoff.CappedAlignment `json:"windows_capped_alignments"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		d.skip("alignment", err.Error())
		return
	}
	if len(parsed.Capped) == 0 {
		d.stage("alignment", "OK", "no sections linked below their requested alignment", nil, nil)
		return
	}
	detail := fmt.Sprintf("%d read-only sections linked below their requested alignment", len(parsed.Capped))
	d.stage("alignment", "WARN", detail, nil, nil)
	var evidence []string
	for _, c := range parsed.Capped {
		evidence = append(evidence, fmt.Sprintf("%s: requested %d, applied %d", c.Section, c.Requested, c.Applied))
	}
	d.finding(findingAlignCapped, "WARN", "alignment", detail, evidence...)
}

var dynamicImport = regexp.MustCompile(`^//go:cgo_import_dynamic\s.*"([^"]+)"\s*$`)

func generatedLibraries(output string) []string {
	seen := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(output, "*.go"))
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if m := dynamicImport.FindStringSubmatch(line); m != nil {
				seen[m[1]] = true
			}
		}
	}
	if manifest, err := os.ReadFile(filepath.Join(output, "bao-manifest.json")); err == nil {
		var parsed struct {
			Imports     []map[string]any `json:"imports"`
			DataImports []map[string]any `json:"data_imports"`
		}
		if json.Unmarshal(manifest, &parsed) == nil {
			for _, imp := range append(parsed.Imports, parsed.DataImports...) {
				for _, key := range []string{"library", "Library", "DLL"} {
					if name, ok := imp[key].(string); ok && name != "" {
						seen[name] = true
					}
				}
			}
		}
	}
	var out []string
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (d *diagnosticSession) checkOrdinals(libraries []string) {
	all := map[string]bool{}
	for _, name := range libraries {
		all[name] = true
	}
	var evidence []string
	if d.flags.assume != "" {
		for _, dep := range strings.Split(d.flags.assume, ",") {
			added, ok := consumerLibraries[strings.TrimSpace(dep)]
			if !ok {
				d.skip("assume-consumer", "no library data for "+dep+"; not counted")
				continue
			}
			for _, name := range added {
				if !all[name] {
					all[name] = true
					evidence = append(evidence, fmt.Sprintf("%s adds %s", dep, name))
				}
			}
		}
	}
	d.limit(findingOrdinal, "ordinals", "dylibs", len(all), machOOrdinalLimit)
	if len(all) > machOOrdinalLimit && len(d.report.Findings) != 0 {
		last := &d.report.Findings[len(d.report.Findings)-1]
		last.Evidence = append(evidence, "cmd/link 1.26.10 keeps only the low 4 bits of ordinals below 128, so ordinal 16 binds to this image")
	}
}

func (d *diagnosticSession) tracePush(symbol, stage string, state []string) {
	trace := d.traces[symbol]
	for i := range trace.Stages {
		if trace.Stages[i].Stage == stage {
			trace.Stages[i].State = append(trace.Stages[i].State, state...)
			return
		}
	}
	trace.Stages = append(trace.Stages, diagnosticTraceStage{stage, state})
}

func traceMatches(symbol, name string) bool {
	if name == symbol || name == "_"+symbol || "_"+name == symbol {
		return true
	}
	return strings.HasPrefix(name, "bao_") && strings.HasSuffix(name, "_"+symbol)
}

func objectSymbolStates(data []byte) map[string]string {
	states := map[string]string{}
	if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		members, err := ar.Parse(data)
		if err != nil {
			return states
		}
		for _, m := range members {
			for name, state := range objectSymbolStates(m.Data) {
				if state == "undefined" && states[name] != "" {
					continue
				}
				states[name] = state
			}
		}
		return states
	}
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		symbols, _ := f.Symbols()
		for _, s := range symbols {
			if s.Section == elf.SHN_UNDEF {
				states[s.Name] = "undefined"
			} else {
				states[s.Name] = "defined"
			}
		}
		return states
	}
	if f, err := macho.NewFile(bytes.NewReader(data)); err == nil && f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Sect == 0 {
				states[s.Name] = "undefined"
			} else {
				states[s.Name] = "defined"
			}
		}
		return states
	}
	if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
		for i := 0; i < len(f.COFFSymbols); {
			s := f.COFFSymbols[i]
			i += 1 + int(s.NumberOfAuxSymbols)
			if name, err := s.FullName(f.StringTable); err == nil {
				if s.SectionNumber == 0 {
					states[name] = "undefined"
				} else {
					states[name] = "defined"
				}
			}
		}
	}
	return states
}

func (d *diagnosticSession) traceStage(stage string, data []byte) {
	if len(d.traces) == 0 {
		return
	}
	states := objectSymbolStates(data)
	for symbol := range d.traces {
		var found []string
		for name, state := range states {
			if traceMatches(symbol, name) {
				found = append(found, name+": "+state)
			}
		}
		sort.Strings(found)
		if len(found) != 0 {
			d.tracePush(symbol, stage, found)
		} else if stage != "generated-symbols" {
			d.tracePush(symbol, stage, []string{"absent"})
		}
	}
}

// traceTranslation compares a symbol's state across the translator. It reports
// what the artifacts show, and labels the responsible stage as an inference.
func (d *diagnosticSession) traceTranslation() {
	for symbol, trace := range d.traces {
		before, after := "", ""
		for _, stage := range trace.Stages {
			state := strings.Join(stage.State, " ")
			switch stage.Stage {
			case "archive", "combined-object":
				before = state
			case "generated-symbols":
				after = state
			}
		}
		line := ""
		switch {
		case after == "":
			d.tracePush(symbol, "generated-symbols", []string{"absent"})
			if strings.Contains(before, ": defined") {
				line = "defined before translation, absent after: inferred alias folding or local renaming"
			}
		case strings.Contains(before, ": undefined") && strings.Contains(after, ": defined"):
			line = "undefined before translation, defined after"
			if strings.HasPrefix(strings.TrimPrefix(symbol, "_"), "section$") {
				line += ": inferred boundary synthesis"
			}
		case strings.Contains(after, ": undefined"):
			line = "still undefined after translation: system import"
		}
		if line != "" {
			d.tracePush(symbol, "translation", []string{line})
		}
	}
}

func (d *diagnosticSession) traceRelocations(data []byte, file string) {
	if len(d.traces) == 0 {
		return
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	symbols, err := f.Symbols()
	if err != nil {
		return
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		content, err := s.Data()
		if err != nil {
			continue
		}
		for i := 0; i+24 <= len(content); i += 24 {
			info := binary.LittleEndian.Uint64(content[i+8:])
			index := info >> 32
			if index == 0 || int(index) > len(symbols) {
				continue
			}
			name := symbols[index-1].Name
			for symbol := range d.traces {
				if traceMatches(symbol, name) {
					kind := elf.R_X86_64(uint32(info)).String()
					if f.Machine == elf.EM_AARCH64 {
						kind = elf.R_AARCH64(uint32(info)).String()
					}
					d.tracePush(symbol, "relocations", []string{fmt.Sprintf("%s %s %s offset %#x", file, s.Name, kind, binary.LittleEndian.Uint64(content[i:]))})
				}
			}
		}
	}
}

// machOBind is one dyld bind recorded in an executable.
type machOBind struct {
	Symbol  string
	Ordinal int
}

// decodeMachOBinds walks a dyld bind opcode stream.
func decodeMachOBinds(stream []byte) ([]machOBind, error) {
	var binds []machOBind
	ordinal, symbol := 0, ""
	uleb := func(at *int) uint64 {
		var v uint64
		for shift := uint(0); *at < len(stream); shift += 7 {
			b := stream[*at]
			*at++
			v |= uint64(b&0x7f) << shift
			if b&0x80 == 0 {
				break
			}
		}
		return v
	}
	for at := 0; at < len(stream); {
		op, imm := stream[at]&0xf0, stream[at]&0x0f
		at++
		switch op {
		case 0x00:
			return binds, nil
		case 0x10:
			ordinal = int(imm)
		case 0x20:
			ordinal = int(uleb(&at))
		case 0x30:
			ordinal = 0
			if imm != 0 {
				ordinal = int(int8(0xf0 | imm))
			}
		case 0x40:
			end := bytes.IndexByte(stream[at:], 0)
			if end < 0 {
				return nil, fmt.Errorf("unterminated bind symbol")
			}
			symbol = string(stream[at : at+end])
			at += end + 1
		case 0x50, 0xb0:
		case 0x60, 0x70, 0x80:
			uleb(&at)
		case 0x90, 0xa0:
			binds = append(binds, machOBind{symbol, ordinal})
			if op == 0xa0 {
				uleb(&at)
			}
		case 0xc0:
			count := uleb(&at)
			uleb(&at)
			for i := uint64(0); i < count; i++ {
				binds = append(binds, machOBind{symbol, ordinal})
			}
		default:
			return nil, fmt.Errorf("unknown bind opcode %#x", op)
		}
		if op == 0xb0 {
			binds = append(binds, machOBind{symbol, ordinal})
		}
	}
	return binds, nil
}

// checkExecutable compares a built Mach-O's binds with the generated manifest.
func (d *diagnosticSession) checkExecutable(f *macho.File, data []byte, manifestPath string) error {
	var stream []byte
	var dylibs []string
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) >= 24 && binary.LittleEndian.Uint32(raw) == 0x80000022 {
			off, size := binary.LittleEndian.Uint32(raw[16:]), binary.LittleEndian.Uint32(raw[20:])
			if uint64(off)+uint64(size) > uint64(len(data)) {
				return fmt.Errorf("bind stream outside executable")
			}
			stream = data[off : off+size]
		}
		if dylib, ok := load.(*macho.Dylib); ok {
			dylibs = append(dylibs, dylib.Name)
		}
	}
	if stream == nil {
		d.skip("final-bind", "no LC_DYLD_INFO bind stream in this executable")
		return nil
	}
	binds, err := decodeMachOBinds(stream)
	if err != nil {
		return err
	}
	var flat []string
	for _, b := range binds {
		if b.Ordinal == -2 {
			flat = append(flat, b.Symbol)
		}
		for symbol := range d.traces {
			if traceMatches(symbol, b.Symbol) {
				d.tracePush(symbol, "final-bind", []string{fmt.Sprintf("%s ordinal %d (%s)", b.Symbol, b.Ordinal, ordinalName(b.Ordinal, dylibs))})
			}
		}
	}
	sort.Strings(flat)
	flat = compactStrings(flat)
	v := len(flat)
	if len(flat) != 0 {
		detail := fmt.Sprintf("%d flat-namespace binds, none are expected", len(flat))
		d.stage("final-bind", "FAIL", detail, &v, nil)
		d.finding(findingFlatBind, "FAIL", "final-bind", detail, flat...)
	} else {
		d.stage("final-bind", "OK", fmt.Sprintf("%d binds across %d dylibs; no flat-namespace binds", len(binds), len(dylibs)), &v, nil)
	}
	if manifestPath == "" {
		d.skip("manifest-compare", "no -manifest given; ordinal corruption not checked")
		return nil
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	expected, err := manifestDarwinImports(manifest)
	if err != nil {
		return err
	}
	if len(expected) == 0 {
		d.skip("manifest-compare", "manifest records no Darwin imports; nothing was compared")
		return nil
	}
	var wrong []string
	for _, b := range binds {
		library, ok := expected[b.Symbol]
		if !ok {
			continue
		}
		if actual := ordinalName(b.Ordinal, dylibs); actual != library {
			wrong = append(wrong, fmt.Sprintf("%s: manifest %s, executable ordinal %d (%s)", b.Symbol, library, b.Ordinal, actual))
		}
	}
	sort.Strings(wrong)
	wrong = compactStrings(wrong)
	w := len(wrong)
	if len(wrong) != 0 {
		detail := fmt.Sprintf("%d binds disagree with the manifest", len(wrong))
		d.stage("manifest-compare", "FAIL", detail, &w, nil)
		d.finding(findingOrdinal, "FAIL", "manifest-compare", detail, wrong...)
	} else {
		d.stage("manifest-compare", "OK", fmt.Sprintf("%d manifest imports match their dylibs", len(expected)), &w, nil)
	}
	return nil
}

// manifestDarwinImports maps each bound Mach-O symbol to its expected dylib.
func manifestDarwinImports(manifest []byte) (map[string]string, error) {
	var parsed struct {
		Imports []struct {
			Remote  string `json:"dynamic_symbol"`
			Library string `json:"library"`
		} `json:"imports"`
	}
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		return nil, err
	}
	expected := map[string]string{}
	for _, imp := range parsed.Imports {
		if imp.Remote != "" && imp.Library != "" {
			expected["_"+imp.Remote] = imp.Library
		}
	}
	return expected, nil
}

func compactStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func ordinalName(ordinal int, dylibs []string) string {
	switch {
	case ordinal == 0:
		return "this image"
	case ordinal == -1:
		return "main executable"
	case ordinal == -2:
		return "flat namespace"
	case ordinal == -3:
		return "weak lookup"
	case ordinal > 0 && ordinal <= len(dylibs):
		return dylibs[ordinal-1]
	}
	return "invalid ordinal"
}

func (d *diagnosticSession) failures() int {
	n := 0
	for _, f := range d.report.Findings {
		if f.Severity == "FAIL" {
			n++
		}
	}
	return n
}
