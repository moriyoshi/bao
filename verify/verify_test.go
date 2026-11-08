package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func signedFixture(t *testing.T) (string, Envelope, Policy) {
	t.Helper()
	root := t.TempDir()
	keydir := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test.invalid/native\ngo 1.26.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binding.go"), []byte("package native\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(keydir, "key")
	if err := KeyPair(key, filepath.Join(keydir, "public")); err != nil {
		t.Fatal(err)
	}
	e, err := Sign(root, "test.invalid/native", "darwin/arm64", "v1", key)
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	b, err := os.ReadFile(filepath.Join(keydir, "public"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	p = Policy{1, map[string][]byte{e.KeyID: public}, []Approval{{"test.invalid/native", "darwin/arm64", "v1", e.KeyID, Digest(e.Payload)}}}
	return root, e, p
}

func TestTrustAndSignedScope(t *testing.T) {
	root, e, p := signedFixture(t)
	m, err := Authenticate(p, []Envelope{e}, "darwin/arm64")
	if err != nil {
		t.Fatal(err)
	}
	files, err := Tree(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = MatchTree(m["test.invalid/native"], files); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"one-byte", "extra-go", "extra-asm", "extra-native"} {
		t.Run(kind, func(t *testing.T) {
			dst := t.TempDir()
			if _, err := Tree(root, dst); err != nil {
				t.Fatal(err)
			}
			name := "binding.go"
			if kind != "one-byte" {
				name = map[string]string{"extra-go": "init.go", "extra-asm": "evil.s", "extra-native": "evil_darwin_arm64.syso"}[kind]
			}
			if err := os.Chmod(dst, 0700); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(filepath.Join(dst, name))
			if err := os.WriteFile(filepath.Join(dst, name), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			files, err := Tree(dst, "")
			if err != nil {
				t.Fatal(err)
			}
			if MatchTree(m["test.invalid/native"], files) == nil {
				t.Fatal("modified scope accepted")
			}
		})
	}
	for _, kind := range []string{"signature", "signer", "target", "release", "payload-pin", "missing"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := json.Marshal(p)
			var policy Policy
			_ = json.Unmarshal(b, &policy)
			b, _ = json.Marshal(e)
			var envelope Envelope
			_ = json.Unmarshal(b, &envelope)
			target := "darwin/arm64"
			envelopes := []Envelope{envelope}
			switch kind {
			case "signature":
				envelopes[0].Signature[0] ^= 1
			case "signer":
				envelopes[0].KeyID = "unknown"
			case "target":
				target = "darwin/amd64"
			case "release":
				policy.Approvals[0].Release = "v2"
			case "payload-pin":
				policy.Approvals[0].PayloadSHA256 = string(bytes.Repeat([]byte{'0'}, 64))
			case "missing":
				envelopes = nil
			}
			if _, err := Authenticate(policy, envelopes, target); err == nil {
				t.Fatal("unapproved signature accepted")
			}
		})
	}
}

func archiveFixture(members ...struct {
	name string
	data []byte
}) []byte {
	b := []byte("!<arch>\n")
	for _, m := range members {
		b = append(b, []byte(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", m.name, 0, 0, 0, 0644, len(m.data)))...)
		b = append(b, m.data...)
		if len(m.data)%2 != 0 {
			b = append(b, 0)
		}
	}
	return b
}
func TestActualArchivePayloads(t *testing.T) {
	type member = struct {
		name string
		data []byte
	}
	native := []byte{0x7f, 'E', 'L', 'F', 1, 2, 3}
	base := []member{{"__.PKGDEF", []byte("package export")}, {"_go_.o", []byte("go object darwin arm64 test")}, {"native.syso", native}}
	expected := PackageInputs{map[string][]string{"native.syso": {Digest(native)}}, map[string]int{"_go_.o": 1}}
	if n, err := CheckArchive(archiveFixture(base...), expected); err != nil || n != 1 {
		t.Fatalf("good archive: %d, %v", n, err)
	}
	for _, kind := range []string{"substituted", "extra", "missing", "duplicate", "forged-go-prefix"} {
		t.Run(kind, func(t *testing.T) {
			m := append([]member(nil), base...)
			switch kind {
			case "substituted":
				m[2].data = append(bytes.Clone(native), 4)
			case "extra":
				m = append(m, member{"evil.syso", native})
			case "missing":
				m = m[:2]
			case "duplicate":
				m = append(m, m[2])
			case "forged-go-prefix":
				m[2].data = []byte("go object attacker native")
			}
			if _, err := CheckArchive(archiveFixture(m...), expected); err == nil {
				t.Fatal("substituted cached payload accepted")
			}
		})
	}
}

func TestTruncatedAssemblyMemberMultiplicity(t *testing.T) {
	// cmd/go truncates ar member names to 16 bytes. Bundled bootstrap assembly
	// files legitimately share this prefix, so identities require counts.
	type member = struct {
		name string
		data []byte
	}
	m := []member{{"__.PKGDEF", []byte("export")}, {"_go_.o", []byte("go object main")}, {"bao_bootstrap_zt", []byte("go object first assembler input")}, {"bao_bootstrap_zt", []byte("go object second assembler input")}}
	p := PackageInputs{GoMembers: map[string]int{"_go_.o": 1, "bao_bootstrap_zt": 2}}
	if _, err := CheckArchive(archiveFixture(m...), p); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckArchive(archiveFixture(append(m, m[2])...), p); err == nil {
		t.Fatal("extra colliding Go object accepted")
	}
	if _, err := CheckArchive(archiveFixture(m[:3]...), p); err == nil {
		t.Fatal("missing colliding Go object accepted")
	}
}

func TestSnapshotsRejectSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := Tree(root, t.TempDir()); err == nil {
		t.Fatal("snapshot followed symlink")
	}
}

func TestLinkUsesCheckedArchiveCopy(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	native := []byte{0x7f, 'E', 'L', 'F', 9}
	b := archiveFixture(struct {
		name string
		data []byte
	}{"__.PKGDEF", []byte("export")}, struct {
		name string
		data []byte
	}{"_go_.o", []byte("go object test")}, struct {
		name string
		data []byte
	}{"native.syso", native})
	source := filepath.Join(root, "cached.a")
	cfg := filepath.Join(root, "importcfg")
	if err := os.WriteFile(source, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("packagefile app="+source+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := HookConfig{Schema: 1, Private: private, Main: "app", Packages: map[string]PackageInputs{"app": {Native: map[string][]string{"native.syso": {Digest(native)}}, GoMembers: map[string]int{"_go_.o": 1}}}}
	args, err := bindLink([]string{"/trusted/link", "-importcfg", cfg, source}, c)
	if err != nil {
		t.Fatal(err)
	}
	checked := args[len(args)-1]
	if checked == source {
		t.Fatal("linker still uses source archive")
	}
	if err = os.WriteFile(source, []byte("substituted after check"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(checked)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("checked archive was not isolated")
	}
	if info, err := os.Stat(checked); err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("archive copy not read-only")
	}
	// Restore directory write permission so t.TempDir cleanup can remove it.
	_ = os.Chmod(filepath.Dir(checked), 0700)
}

func TestAmbiguousPolicyJSONRejected(t *testing.T) {
	for _, b := range []string{`{"schema":1,"schema":2}`, `{"keys":{"a":"first","a":"second"}}`, `{"schema":1} {"schema":2}`} {
		var p Policy
		if Decode([]byte(b), &p) == nil {
			t.Fatalf("ambiguous JSON accepted: %s", b)
		}
	}
}

func TestAssemblyIncludeEscapeRejected(t *testing.T) {
	dir := t.TempDir()
	for _, line := range []string{"#include \"../../outside.h\"", "#/**/include \"/outside.h\"", "# include HEADER_MACRO", "#include \\\n\"../../outside.h\""} {
		if err := os.WriteFile(filepath.Join(dir, "binding.s"), []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		if checkAssembly(dir, []string{"binding.s"}) == nil {
			t.Fatalf("include escape accepted: %s", line)
		}
	}
}
