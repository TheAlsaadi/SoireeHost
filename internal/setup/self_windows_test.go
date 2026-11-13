//go:build windows

// Regression tests for DR-9 (docs/reviews/2026-11-12-skills-review.md):
// setup copies the program it checked and opened at start, not whatever sits
// at its launch path later, and refuses to run from a folder another account
// could change.

package setup

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

func hashFile(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- test
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func me(t *testing.T) string {
	t.Helper()
	c, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	return c.SID
}

// While setup holds the program open, nobody can rename it away and put
// another file at its path; the copy is the running image.
func TestOpenSelfHoldsTheProgram(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	img, err := openSelf(self, me(t))
	if err != nil {
		t.Fatalf("openSelf on the test binary: %v", err)
	}
	defer img.Close() //nolint:errcheck // test
	moved := self + ".moved"
	if err := os.Rename(self, moved); err == nil {
		_ = os.Rename(moved, self)
		t.Fatal("the program could be renamed while setup held it open")
	}
	dst := filepath.Join(t.TempDir(), "Program Files", "SoireeHost", "soireehost.exe")
	if err := copyBinary(img, self, dst); err != nil {
		t.Fatal(err)
	}
	if hashFile(t, dst) != hashFile(t, self) {
		t.Fatal("installed copy differs from the running image")
	}
}

// A folder in which another account (here Authenticated Users) may write is
// refused before anything is opened or copied.
func TestOpenSelfRefusesFolderOthersCanChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	sddl := "D:P(A;OICI;FA;;;" + me(t) + ")(A;OICI;0x1301bf;;;" + winsec.SIDAuthenticated + ")"
	if err := winsec.SetFolderSDDL(dir, sddl); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "soireehost.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openSelf(exe, me(t))
	if err == nil || !strings.Contains(err.Error(), "refusing to install") {
		t.Fatalf("got %v, want a refusal", err)
	}
}
