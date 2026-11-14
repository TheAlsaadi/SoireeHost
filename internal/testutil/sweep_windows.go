package testutil

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// SweepFiles reads every file under root and fails the test for each one
// that contains needle (an S-40 canary sweep, plan section 10). A folder or
// file it cannot read also fails the test, because a sweep that cannot read
// something proves nothing about it; a file that vanishes during the walk
// (a temporary file) is skipped. read reads one file; nil means
// os.ReadFile. It returns the files read, so the caller can assert that the
// sweep saw what it should (review finding GOE-12).
func SweepFiles(t testing.TB, root string, needle []byte, read func(string) ([]byte, error)) []string {
	t.Helper()
	if read == nil {
		read = os.ReadFile
	}
	var seen []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p != root {
				return nil
			}
			t.Errorf("canary sweep cannot read %s: %v", p, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, err := read(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			t.Errorf("canary sweep cannot read %s: %v", p, err)
			return nil
		}
		seen = append(seen, p)
		if bytes.Contains(b, needle) {
			t.Errorf("%s contains the canary in clear", p)
		}
		return nil
	})
	if err != nil {
		t.Errorf("canary sweep of %s: %v", root, err)
	}
	if len(seen) == 0 {
		t.Errorf("canary sweep of %s read no files", root)
	}
	return seen
}

// Under reports how many of paths lie inside dir.
func Under(paths []string, dir string) int {
	n := 0
	for _, p := range paths {
		if rel, err := filepath.Rel(dir, p); err == nil && rel != "." && !filepath.IsAbs(rel) && rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator))) {
			n++
		}
	}
	return n
}
