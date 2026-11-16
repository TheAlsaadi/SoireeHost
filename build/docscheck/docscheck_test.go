package docscheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// repoRoot is two levels up from this package.
const repoRoot = "../.."

// documents name the tests that prove requirements.
var documents = []string{
	"docs/SECURITY_CHECKLIST.md",
	"docs/TEST_PLAN.md",
	"docs/PLAN.md",
	"docs/adr/*.md",
}

var (
	// a Go test or fuzz target named in backticks, such as `TestUnknownHost`
	docGoTest = regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`")
	// a frontend test file named in backticks, such as `Activity.test.ts`
	docTSTest = regexp.MustCompile("`(?:[A-Za-z0-9_/.-]*/)?([A-Za-z0-9_-]+\\.test\\.ts)`")
	goTestDef = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
)

// skipDirs are never searched for tests.
var skipDirs = []string{".git", ".claude", "node_modules", "dist", "bin", ".cache"}

// TestDocumentedTestsExist fails when a document names a test that no test
// file defines (CLAUDE.md: every S-ID maps to a test).
func TestDocumentedTestsExist(t *testing.T) {
	goTests := map[string]bool{}
	tsFiles := map[string]bool{}
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != repoRoot && slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, "_test.go"):
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range goTestDef.FindAllSubmatch(src, -1) {
				goTests[string(m[1])] = true
			}
		case strings.HasSuffix(path, ".test.ts"):
			tsFiles[d.Name()] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(goTests) == 0 || len(tsFiles) == 0 {
		t.Fatalf("found %d Go tests and %d frontend test files; the search is broken", len(goTests), len(tsFiles))
	}

	named := 0
	for _, pattern := range documents {
		paths, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pattern)))
		if err != nil || len(paths) == 0 {
			t.Fatalf("no document matches %s (%v)", pattern, err)
		}
		for _, path := range paths {
			text, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(repoRoot, path)
			for _, m := range docGoTest.FindAllSubmatch(text, -1) {
				named++
				if !goTests[string(m[1])] {
					t.Errorf("%s names %s, which no test file defines", filepath.ToSlash(rel), m[1])
				}
			}
			for _, m := range docTSTest.FindAllSubmatch(text, -1) {
				named++
				if !tsFiles[string(m[1])] {
					t.Errorf("%s names %s, which does not exist", filepath.ToSlash(rel), m[1])
				}
			}
		}
	}
	if named < 100 {
		t.Errorf("the documents name only %d tests; the patterns are broken", named)
	}
}
