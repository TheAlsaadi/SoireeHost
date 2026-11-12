package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The test binary itself is a Go-built 64-bit Windows executable, so it
// should carry the same default mitigations as soireehost.exe.
func TestCheckOwnExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	missing, err := check(exe)
	if err != nil {
		t.Skipf("cannot inspect test binary: %v", err)
	}
	if len(missing) > 0 {
		t.Errorf("test binary is missing %v", missing)
	}
}

func TestCheckRejectsNonPE(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not.exe")
	if err := os.WriteFile(p, []byte("MZ but not really"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := check(p); err == nil {
		t.Error("check accepted a file that is not a PE image")
	}
}
