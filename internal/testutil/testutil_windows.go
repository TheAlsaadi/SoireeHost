// Package testutil has helpers shared by tests. It is imported only from
// _test.go files and never ends up in soireehost.exe.
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Junction creates a directory junction at link pointing to target. Creating a
// junction needs no administrator rights.
func Junction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "cmd.exe", "/c", "mklink", "/J", filepath.Clean(link), filepath.Clean(target)) // #nosec G204 -- test helper; both arguments are paths the test created
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v\n%s", link, target, err, out)
	}
}

// SiteDir returns a fresh, empty folder that is safe to publish as a static
// root in tests. t.TempDir() lives under %LOCALAPPDATA%, which SoiréeHost
// refuses to publish (S-11), so this one is created in the test's working
// directory instead (the package folder) and removed afterwards.
func SiteDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(".", "testsite-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(abs); err != nil {
			t.Errorf("removing %s: %v", abs, err)
		}
	})
	return abs
}
