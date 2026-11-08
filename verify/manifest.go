// Package verify implements Bao's explicitly invoked, consumer-controlled
// verification profile. It does not establish trust in publishers or hosts.
package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const domain = "bao.module-release.v1\x00"

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema  int    `json:"schema"`
	Module  string `json:"module"`
	Target  string `json:"target"`
	Release string `json:"release"`
	Files   []File `json:"files"`
}
type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Approval struct {
	Module        string `json:"module"`
	Target        string `json:"target"`
	Release       string `json:"release"`
	KeyID         string `json:"key_id"`
	PayloadSHA256 string `json:"payload_sha256"`
}
type Policy struct {
	Schema    int               `json:"schema"`
	Keys      map[string][]byte `json:"keys"`
	Approvals []Approval        `json:"approvals"`
}

func Digest(b []byte) string             { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func KeyID(key ed25519.PublicKey) string { return Digest(key) }

func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected one Ed25519 public PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key must be Ed25519")
	}
	return pub, nil
}

func Decode(b []byte, dst any) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("JSON must be UTF-8")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON value")
	}
	return nil
}

func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}
			k, ok := t.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if seen[k] {
				return fmt.Errorf("duplicate JSON key %q", k)
			}
			seen[k] = true
			if err = uniqueJSON(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueJSON(d); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func KeyPair(privatePath, publicPath string) error {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err = WriteNew(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0600); err != nil {
		return err
	}
	b, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return WriteNew(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}), 0644)
}
func WriteNew(name string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func Sign(root, module, target, release, keyPath string) (Envelope, error) {
	var result Envelope
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return result, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return result, fmt.Errorf("expected one PKCS8 Ed25519 PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return result, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return result, fmt.Errorf("key must be Ed25519")
	}
	files, err := Tree(root, "")
	if err != nil {
		return result, err
	}
	m := Manifest{1, module, target, release, files}
	if err = validateManifest(m); err != nil {
		return result, err
	}
	b, err = json.Marshal(m)
	if err != nil {
		return result, err
	}
	return Envelope{KeyID(key.Public().(ed25519.PublicKey)), b, ed25519.Sign(key, append([]byte(domain), b...))}, nil
}

func Authenticate(policy Policy, envelopes []Envelope, target string) (map[string]Manifest, error) {
	if policy.Schema != 1 || len(policy.Keys) == 0 || len(policy.Approvals) == 0 {
		return nil, fmt.Errorf("policy requires schema 1, independent keys and explicit approvals")
	}
	for id, key := range policy.Keys {
		if len(key) != ed25519.PublicKeySize || KeyID(key) != id {
			return nil, fmt.Errorf("invalid trusted key %q", id)
		}
	}
	out := map[string]Manifest{}
	for _, e := range envelopes {
		key, ok := policy.Keys[e.KeyID]
		if !ok || !ed25519.Verify(key, append([]byte(domain), e.Payload...), e.Signature) {
			return nil, fmt.Errorf("unauthorized signer or invalid signature")
		}
		var m Manifest
		if err := Decode(e.Payload, &m); err != nil {
			return nil, err
		}
		if err := validateManifest(m); err != nil {
			return nil, err
		}
		if m.Target != target {
			return nil, fmt.Errorf("manifest target %s differs from build target %s", m.Target, target)
		}
		approved := false
		for _, a := range policy.Approvals {
			if a.Module == m.Module && a.Target == target && a.Release == m.Release && a.KeyID == e.KeyID && a.PayloadSHA256 == Digest(e.Payload) {
				approved = true
			}
		}
		if !approved {
			return nil, fmt.Errorf("release %s of %s is not pinned by policy", m.Release, m.Module)
		}
		if _, ok := out[m.Module]; ok {
			return nil, fmt.Errorf("duplicate manifest for %s", m.Module)
		}
		out[m.Module] = m
	}
	for _, a := range policy.Approvals {
		if a.Target == target {
			if _, ok := out[a.Module]; !ok {
				return nil, fmt.Errorf("missing approved manifest for %s", a.Module)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no approved manifests for target %s", target)
	}
	return out, nil
}

func validateManifest(m Manifest) error {
	if m.Schema != 1 || m.Module == "" || m.Release == "" || !strings.Contains(m.Target, "/") || len(m.Files) == 0 {
		return fmt.Errorf("invalid module release manifest")
	}
	previous := ""
	hasMod := false
	for _, f := range m.Files {
		if f.Path <= previous || !safePath(f.Path) || len(f.SHA256) != 64 {
			return fmt.Errorf("invalid, duplicate or unordered manifest file %q", f.Path)
		}
		if _, err := hex.DecodeString(f.SHA256); err != nil {
			return err
		}
		previous = f.Path
		hasMod = hasMod || f.Path == "go.mod"
	}
	if !hasMod {
		return fmt.Errorf("signed module must include go.mod")
	}
	return nil
}
func safePath(s string) bool {
	return utf8.ValidString(s) && s != "" && s != "." && !strings.Contains(s, "\\") && !strings.ContainsAny(s, "\x00\r\n") && !path.IsAbs(s) && path.Clean(s) == s && !strings.HasPrefix(s, "../")
}

// Tree hashes the exact bytes copied to dst, when provided. Only .git metadata
// is excluded. Symlinks and special files fail closed. Destination is private.
func Tree(root, dst string) ([]File, error) {
	var files []File
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == ".git" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink not supported in verified module: %s", p)
		}
		if d.IsDir() {
			if dst != "" {
				return os.MkdirAll(filepath.Join(dst, rel), 0700)
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special file: %s", p)
		}
		rel = filepath.ToSlash(rel)
		if !safePath(rel) {
			return fmt.Errorf("unsafe file path %q", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if dst != "" {
			if err = WriteNew(filepath.Join(dst, filepath.FromSlash(rel)), b, 0400); err != nil {
				return err
			}
		}
		files = append(files, File{rel, Digest(b)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

func MatchTree(m Manifest, files []File) error {
	if len(m.Files) != len(files) {
		return fmt.Errorf("module %s file set differs from signed release", m.Module)
	}
	for i, f := range files {
		if f != m.Files[i] {
			return fmt.Errorf("module %s: signed bytes differ at %s", m.Module, f.Path)
		}
	}
	return nil
}
