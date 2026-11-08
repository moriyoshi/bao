package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/moriyoshi/bao/verify"
)

func signatureCommand(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	fs := newFlags(command, command+" [options]", "Consumer-controlled module signatures and isolated verified builds. Read README.md#consumer-controlled-signature-verification for the trust boundary.")
	if command == "keygen" {
		private := fs.String("private", "", "new PKCS8 Ed25519 private PEM file")
		public := fs.String("public", "", "new public PEM file")
		if err := parseFlags(fs, args, stdout); err != nil {
			return err
		}
		if *private == "" || *public == "" || fs.NArg() != 0 {
			return usage("keygen requires -private and -public")
		}
		if err := verify.KeyPair(*private, *public); err != nil {
			return err
		}
		b, err := os.ReadFile(*public)
		if err != nil {
			return err
		}
		pub, err := verify.ParsePublicKey(b)
		if err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"key_id": verify.KeyID(pub), "public_key": []byte(pub)})
	}
	if command == "sign" {
		root := fs.String("root", ".", "complete module directory; includes Go/assembly/native bytes; no symlinks")
		module := fs.String("module", "", "module import path")
		target := fs.String("target", "", "exact GOOS/GOARCH")
		release := fs.String("release", "", "release identity")
		key := fs.String("key", "", "PKCS8 Ed25519 private PEM, outside module")
		out := fs.String("o", "", "new signed JSON envelope, outside module")
		if err := parseFlags(fs, args, stdout); err != nil {
			return err
		}
		if fs.NArg() != 0 || *module == "" || *target == "" || *release == "" || *key == "" || *out == "" {
			return usage("sign requires -module, -target, -release, -key and -o")
		}
		r, err := filepath.Abs(*root)
		if err != nil {
			return err
		}
		for _, p := range []string{*key, *out} {
			p, err = filepath.Abs(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(r, p)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return usage("private key and envelope must be outside signed module")
			}
		}
		e, err := verify.Sign(r, *module, *target, *release, *key)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			return err
		}
		if err = verify.WriteNew(*out, append(b, '\n'), 0644); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]string{"key_id": e.KeyID, "payload_sha256": verify.Digest(e.Payload)})
	}
	policy := fs.String("policy", "", "independently trusted consumer policy JSON; required for native dependencies")
	var manifests symbolFlags
	fs.Var(&manifests, "manifest", "signed module envelope, repeatable")
	target := fs.String("target", runtime.GOOS+"/"+runtime.GOARCH, "GOOS/GOARCH")
	dir := fs.String("C", ".", "consumer module working directory; workspaces disabled")
	goTool := fs.String("go", "go", "trusted stock Go 1.26.10 executable")
	scanOnly := command == "verify"
	out := new(string)
	asJSON := new(bool)
	backend, bazel := new(string), new(string)
	*backend = "go"
	var moduleRoots symbolFlags
	if scanOnly {
		asJSON = fs.Bool("json", false, "print the source scan report as JSON, including rejected dependencies")
	} else {
		out = fs.String("o", "", "new executable output path (required)")
		backend = fs.String("backend", "go", "build backend: go or bazel")
		bazel = fs.String("bazel", "bazel", "trusted Bazel 8.4.2 executable (Bazel backend)")
		fs.Var(&moduleRoots, "module", "approved module=workspace-relative root, repeatable (Bazel backend)")
	}
	if err := parseFlags(fs, args, stdout); err != nil {
		return err
	}
	if scanOnly && (fs.NArg() != 0 || (*policy == "") != (len(manifests) == 0)) {
		return usage("verify accepts no package arguments; supply -policy and -manifest together to authenticate native dependencies")
	}
	if !scanOnly && (*policy == "" || len(manifests) == 0 || *out == "" || fs.NArg() > 1) {
		return usage("verified-build requires -policy, -manifest and -o, plus at most one main package")
	}
	if !scanOnly && (*backend != "go" && *backend != "bazel" || *backend == "go" && len(moduleRoots) != 0 || *backend == "bazel" && (fs.NArg() != 1 || len(moduleRoots) == 0)) {
		return usage("verified-build -backend bazel requires one //package:target and -module importpath=relative/root; -backend go does not accept -module")
	}
	roots := map[string]string{}
	for _, value := range moduleRoots {
		module, root, ok := strings.Cut(value, "=")
		if !ok || module == "" || root == "" || roots[module] != "" {
			return usage("each -module must specify a unique importpath=relative/root")
		}
		roots[module] = root
	}
	var p verify.Policy
	if *policy != "" {
		b, err := os.ReadFile(*policy)
		if err != nil {
			return err
		}
		if err = verify.Decode(b, &p); err != nil {
			return err
		}
	}
	var envelopes []verify.Envelope
	for _, name := range manifests {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		var e verify.Envelope
		if err = verify.Decode(b, &e); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		envelopes = append(envelopes, e)
	}
	directory, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if scanOnly {
		report, scanErr := verify.Scan(ctx, verify.ScanOptions{Directory: directory, Go: *goTool, Target: *target, Policy: p, Envelopes: envelopes, Stderr: stderr})
		if *asJSON {
			if err := writeJSON(stdout, report); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(stdout, "Scope:", report.Scope)
			for _, m := range report.Modules {
				fmt.Fprintf(stdout, "%s: %s (%d native files)\n", m.Path, m.Status, len(m.NativeFiles))
			}
			fmt.Fprintf(stdout, "Scanned %d dependencies; authenticated %d native module sources.\n", len(report.Modules), len(report.Authenticated))
		}
		return scanErr
	}
	bao, err := os.Executable()
	if err != nil {
		return err
	}
	output, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	pkg := "."
	if fs.NArg() == 1 {
		pkg = fs.Arg(0)
	}
	var report verify.BuildReport
	if *backend == "bazel" {
		report, err = verify.BazelBuild(ctx, verify.BazelOptions{Directory: directory, Bazel: *bazel, Target: *target, Output: output, Package: pkg, Policy: p, Envelopes: envelopes, ModuleRoots: roots, Stdout: stdout, Stderr: stderr})
	} else {
		report, err = verify.Build(ctx, verify.BuildOptions{Directory: directory, Go: *goTool, Bao: bao, Target: *target, Output: output, Package: pkg, Policy: p, Envelopes: envelopes, Stdout: stdout, Stderr: stderr})
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, report)
}
