// bao-release packages already-built CLI executables. It never compiles native
// helpers or signs a generated native module.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var targets = []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64", "linux_loong64", "linux_ppc64le"}
var tagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type options struct {
	root, stage, out, version, commit string
	epoch                             int64
}

func main() {
	var o options
	flag.StringVar(&o.root, "root", ".", "source workspace for license texts")
	flag.StringVar(&o.stage, "stage", "", "directory containing TARGET/bao for all six CLI hosts")
	flag.StringVar(&o.out, "out", "", "new output directory (never overwritten)")
	flag.StringVar(&o.version, "version", "", "release tag, including v")
	flag.StringVar(&o.commit, "commit", "", "full source Git commit")
	flag.Int64Var(&o.epoch, "epoch", 0, "source commit Unix timestamp")
	flag.Parse()
	err := errors.New("unexpected positional arguments")
	if flag.NArg() == 0 {
		err = run(o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bao-release:", err)
		os.Exit(1)
	}
}

func validate(o options) error {
	if !tagPattern.MatchString(o.version) || !commitPattern.MatchString(o.commit) || o.epoch <= 0 || o.epoch > 1<<32-1 {
		return errors.New("require SemVer v-tag, lowercase 40-hex commit and positive 32-bit Unix timestamp")
	}
	base := strings.SplitN(o.version, "+", 2)[0]
	if _, pre, ok := strings.Cut(base, "-"); ok {
		for _, part := range strings.Split(pre, ".") {
			if len(part) > 1 && part[0] == '0' && strings.Trim(part, "0123456789") == "" {
				return errors.New("numeric prerelease identifiers must not start with zero")
			}
		}
	}
	if o.stage == "" || o.out == "" {
		return errors.New("require -stage and -out")
	}
	return nil
}

func run(o options) (err error) {
	if err := validate(o); err != nil {
		return err
	}
	// Read all inputs before creating any output. Fixed names prevent path
	// traversal and ensure incomplete matrices cannot be published accidentally.
	common := map[string][]byte{}
	for name, source := range map[string]string{
		"LICENSE":                     "LICENSE",
		"licenses/LICENSE-GO.txt":     "bindings/bootstrap/LICENSE-GO.txt",
		"licenses/LICENSE-PUREGO.txt": "bindings/bootstrap/LICENSE-PUREGO.txt",
		"licenses/provenance.json":    "bindings/bootstrap/provenance.json",
	} {
		b, err := os.ReadFile(filepath.Join(o.root, source))
		if err != nil {
			return err
		}
		common[name] = b
	}
	common["NOTICE"] = []byte("Bao is licensed under Apache-2.0.\n" +
		"Generated binding bootstrap templates embedded in Bao derive from\n" +
		"github.com/ebitengine/purego v0.11.3 and the Go runtime.\n" +
		"Their copyright notices remain in the embedded source templates;\n" +
		"upstream license texts and provenance hashes accompany this distribution.\n" +
		"See licenses/ and https://github.com/moriyoshi/bao for sources.\n")
	metadata, err := json.MarshalIndent(struct {
		Version string   `json:"version"`
		Commit  string   `json:"commit"`
		Epoch   int64    `json:"source_date_epoch"`
		Go      string   `json:"go"`
		Bazel   string   `json:"bazel"`
		Hosts   []string `json:"cli_hosts"`
	}{o.version, o.commit, o.epoch, "1.26.10", "8.4.2", targets}, "", "  ")
	if err != nil {
		return err
	}
	metadata = append(metadata, '\n')
	common["release.json"] = metadata
	binaries := map[string][]byte{}
	for _, target := range targets {
		b, err := os.ReadFile(filepath.Join(o.stage, target, "bao"))
		if err != nil {
			return err
		}
		if err := checkBinary(b, target); err != nil {
			return fmt.Errorf("%s: %w", target, err)
		}
		binaries[target] = b
	}
	if err := os.Mkdir(o.out, 0o755); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(o.out)
		}
	}()
	checksums := map[string]string{}
	write := func(name string, b []byte) error {
		d := sha256.Sum256(b)
		checksums[name] = hex.EncodeToString(d[:])
		return os.WriteFile(filepath.Join(o.out, name), b, 0o644)
	}
	for _, target := range targets {
		name := "bao_" + o.version + "_" + target
		b, e := archive(name, binaries[target], common, time.Unix(o.epoch, 0).UTC())
		if e != nil {
			return e
		}
		if err = write(name+".tar.gz", b); err != nil {
			return err
		}
	}
	if err = write("release.json", metadata); err != nil {
		return err
	}
	names := make([]string, 0, len(checksums))
	for name := range checksums {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", checksums[name], name)
	}
	return os.WriteFile(filepath.Join(o.out, "SHA256SUMS"), []byte(sums.String()), 0o644)
}

func checkBinary(b []byte, target string) error {
	if strings.HasPrefix(target, "darwin_") {
		f, err := macho.NewFile(bytes.NewReader(b))
		if err != nil {
			return err
		}
		want := macho.CpuArm64
		if target == "darwin_amd64" {
			want = macho.CpuAmd64
		}
		if f.Cpu != want || f.Type != macho.TypeExec {
			return errors.New("wrong Mach-O executable architecture/type")
		}
		return nil
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return err
	}
	want := map[string]elf.Machine{"linux_amd64": elf.EM_X86_64, "linux_arm64": elf.EM_AARCH64, "linux_loong64": elf.EM_LOONGARCH, "linux_ppc64le": elf.EM_PPC64}[target]
	if f.Machine != want || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_EXEC {
		return errors.New("wrong ELF executable architecture/type/endianness")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("CLI unexpectedly requires a dynamic ELF interpreter")
		}
	}
	return nil
}

func archive(prefix string, binary []byte, common map[string][]byte, timestamp time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.ModTime = timestamp
	gz.OS = 255
	tw := tar.NewWriter(gz)
	files := map[string][]byte{"bao": binary}
	for name, data := range common {
		files[name] = data
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		mode := int64(0o644)
		if name == "bao" {
			mode = 0o755
		}
		h := &tar.Header{Name: prefix + "/" + name, Mode: mode, Size: int64(len(files[name])), ModTime: timestamp, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tw, bytes.NewReader(files[name])); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
