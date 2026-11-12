package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// buildProbe compiles a tiny program the way release builds are made
// (CGO off, -trimpath) and returns its path. The test binary itself is not
// used: under -race it is linked differently and lacks some flags.
func buildProbe(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module probe\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "probe.exe")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", out, ".") //nolint:gosec // G204: fixed command; out is under t.TempDir
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=", "GOOS=windows", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building probe: %v\n%s", err, b)
	}
	return out
}

func TestCheckReleaseStyleBinary(t *testing.T) {
	missing, err := check(buildProbe(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Errorf("CGO-off build is missing %v", missing)
	}
}

func TestCheckReportsClearedFlags(t *testing.T) {
	src := buildProbe(t)
	data, err := os.ReadFile(src) //nolint:gosec // G304: path comes from t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	// PE32+: DllCharacteristics sits 70 bytes into the optional header,
	// which follows the 4-byte signature and the 20-byte COFF header.
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:]))
	at := peOffset + 4 + 20 + 70
	flags := binary.LittleEndian.Uint16(data[at:])
	binary.LittleEndian.PutUint16(data[at:], flags&^(dynamicBase|highEntropyVA|nxCompat))

	stripped := filepath.Join(t.TempDir(), "stripped.exe")
	if err := os.WriteFile(stripped, data, 0o600); err != nil { //nolint:gosec // G703: path is under t.TempDir
		t.Fatal(err)
	}
	missing, err := check(stripped)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ASLR (DYNAMIC_BASE)", "high-entropy ASLR (HIGH_ENTROPY_VA)", "DEP (NX_COMPAT)"}
	if !reflect.DeepEqual(missing, want) {
		t.Errorf("missing = %v, want %v", missing, want)
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
