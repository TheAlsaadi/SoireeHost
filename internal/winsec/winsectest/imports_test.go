package winsectest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestImportedOnlyFromTests fails if a Go file that ships imports this package
// (SE-03). It parses every file itself, so files behind any build tag count.
func TestImportedOnlyFromTests(t *testing.T) {
	const pkg = "github.com/TheAlsaadi/SoireeHost/internal/winsec/winsectest"
	root := filepath.Join("..", "..", "..")
	var shipped, fromTests int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			// The go command ignores dot and underscore folders and testdata.
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		isTest := strings.HasSuffix(name, "_test.go")
		if !isTest {
			shipped++
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if p != pkg {
				continue
			}
			if isTest {
				fromTests++
			} else {
				t.Errorf("%s imports %s, which is for tests only", path, pkg)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guard against a scan that passes because it looked at nothing.
	if shipped == 0 || fromTests == 0 {
		t.Fatalf("scan found %d shipped files and %d test imports; the root or package path is wrong", shipped, fromTests)
	}
}
