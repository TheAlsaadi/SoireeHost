package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteAtomic: a new file is created, an existing one replaced whole, and
// no temporary file is left behind either way.
func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, data := range []string{`{"v":1}`, `{"v":2,"longer":true}`, `{}`} {
		if err := WriteAtomic(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path) // #nosec G304 -- the test's own temporary file
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != data {
			t.Fatalf("file holds %q, want %q", got, data)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("folder holds %v, want only state.json", names)
	}
}

// TestWriteAtomicMissingFolder: a write into a folder that does not exist
// fails and creates nothing.
func TestWriteAtomicMissingFolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "state.json")
	if err := WriteAtomic(path, []byte("x")); err == nil {
		t.Fatal("WriteAtomic into a missing folder succeeded")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("folder was created: %v", err)
	}
}
