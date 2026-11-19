package winsec

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func signatureOf(t *testing.T, path string) Signature {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304, G703: this test's own files and a fixed system program
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	sig, err := FileSignature(path, windows.Handle(f.Fd()))
	if err != nil {
		t.Fatalf("FileSignature(%s): %v", path, err)
	}
	return sig
}

// TestFileSignature: an unsigned program is not Valid; a program signed by
// Microsoft is, with its publisher's name; and the same program with one
// byte changed is not (S-61). The check runs offline.
func TestFileSignature(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if sig := signatureOf(t, self); sig.Valid || sig.Subject != "" {
		t.Fatalf("this unsigned test binary reads as %+v", sig)
	}
	signed := filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe")
	if _, err := os.Stat(signed); err != nil { //nolint:gosec // G703: a fixed system program
		t.Skipf("no signed sample here (%v)", err)
	}
	sig := signatureOf(t, signed)
	if !sig.Valid || sig.Subject != "Microsoft Corporation" {
		t.Fatalf("msedge.exe reads as %+v", sig)
	}
	b, err := os.ReadFile(signed) //nolint:gosec // G304, G703: a fixed system program
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/3] ^= 0x01
	changed := filepath.Join(t.TempDir(), "changed.exe")
	if err := os.WriteFile(changed, b, 0o600); err != nil { //nolint:gosec // G703: a file in this test's own temporary folder
		t.Fatal(err)
	}
	if sig := signatureOf(t, changed); sig.Valid {
		t.Fatalf("a changed copy of msedge.exe still verifies: %+v", sig)
	}
}
