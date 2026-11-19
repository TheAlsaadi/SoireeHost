package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/update"
)

func emptyKeys(t *testing.T, dir string) string {
	t.Helper()
	b, err := update.EncodeKeys()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenAndCheck(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	keys := emptyKeys(t, repo)
	key := filepath.Join(outside, "update.key")
	id, err := gen(key, keys, repo)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	got, err := check(key, keys)
	if err != nil || got != id {
		t.Fatalf("check = %q, %v; want %q", got, err, id)
	}
	b, _ := os.ReadFile(keys) //nolint:gosec // G304: a file this test created
	if !strings.Contains(string(b), id) {
		t.Fatalf("keys.json does not list %s:\n%s", id, b)
	}
	// the key file never appears in keys.json, and the key never in output
	kb, _ := os.ReadFile(key) //nolint:gosec // G304: a file this test created
	if strings.Contains(string(b), strings.TrimSpace(string(kb))) {
		t.Fatal("the private key leaked into keys.json")
	}
	if _, err := gen(key, keys, repo); err == nil {
		t.Fatal("gen overwrote an existing private key file")
	}
	// a second key for a rotation, then no third
	if _, err := gen(filepath.Join(outside, "next.key"), keys, repo); err != nil {
		t.Fatalf("second key: %v", err)
	}
	if _, err := gen(filepath.Join(outside, "third.key"), keys, repo); err == nil {
		t.Fatal("gen accepted a third trusted key")
	}
	if ks, _ := readKeys(keys); len(ks) != 2 {
		t.Fatalf("keys.json holds %d keys, want 2", len(ks))
	}
}

func TestGenRefusesInsideRepository(t *testing.T) {
	repo := t.TempDir()
	keys := emptyKeys(t, repo)
	for _, p := range []string{
		filepath.Join(repo, "update.key"),
		filepath.Join(repo, "sub", "update.key"),
		strings.ToUpper(filepath.Join(repo, "update.key")),
	} {
		if _, err := gen(p, keys, repo); err == nil {
			t.Errorf("gen wrote a private key at %s, inside the repository", p)
		}
	}
	if _, err := gen("", keys, repo); err == nil {
		t.Error("gen accepted an empty -out")
	}
}

func TestCheckRefusesUntrustedKey(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	keys := emptyKeys(t, repo)
	other := filepath.Join(repo, "other.json")
	if err := os.WriteFile(other, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(outside, "update.key")
	if _, err := gen(key, other, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := check(key, keys); err == nil {
		t.Fatal("check trusted a key that keys.json does not list")
	}
	bad := filepath.Join(outside, "bad.key")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := check(bad, keys); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("check of a malformed key = %v (must fail without echoing the file)", err)
	}
}

func TestInside(t *testing.T) {
	root := filepath.Join("C:\\", "repo")
	for p, want := range map[string]bool{
		root:                                     true,
		filepath.Join(root, "a"):                 true,
		filepath.Join("C:\\", "REPO", "a"):       true,
		filepath.Join("C:\\", "repo2", "a"):      false,
		filepath.Join("C:\\", "other"):           false,
		filepath.Join("D:\\", "repo"):            false,
		filepath.Join("C:\\", "repo", "..", "x"): false,
	} {
		if got := inside(p, root); got != want {
			t.Errorf("inside(%s) = %v, want %v", p, got, want)
		}
	}
}
