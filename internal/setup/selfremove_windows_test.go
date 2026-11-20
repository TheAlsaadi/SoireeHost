package setup

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// testRemovedSDDL is removedFolderSDDL plus the account running the test,
// which on a developer PC is not an administrator.
func testRemovedSDDL(t *testing.T) string {
	t.Helper()
	me, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me.SID + ")"
}

func leftovers(t *testing.T, parent string) []string {
	t.Helper()
	es, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// TestRemoveProgramFolderNothingInUse: with nothing running, the whole
// folder goes at once and no folder for the restart is made.
func TestRemoveProgramFolderNothingInUse(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "SoireeHost")
	if err := os.MkdirAll(filepath.Join(dir, "rollback", "history"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"soireehost.exe", "cloudflared.exe", "soireehost.exe.previous", filepath.Join("rollback", "history", "1.json")} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved, err := removeProgramFolder(dir, testRemovedSDDL(t))
	if err != nil || len(moved) != 0 {
		t.Fatalf("removeProgramFolder = %v, %v", moved, err)
	}
	if left := leftovers(t, parent); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	// a folder that is already gone is fine
	if _, err := removeProgramFolder(dir, testRemovedSDDL(t)); err != nil {
		t.Fatalf("second removal: %v", err)
	}
}

// TestRemoveProgramFolderWhileRunning: the program folder goes even while a
// program in it runs, as uninstall's own program does. The running file is
// moved aside into the protected .removed- folder for the next restart, and
// everything else is deleted at once.
func TestRemoveProgramFolderWhileRunning(t *testing.T) {
	if os.Getenv("SOIREEHOST_SELFREMOVE_HELPER") == "1" {
		t.Skip("helper run")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "SoireeHost")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "soireehost.exe")
	copyFile(t, self, exe)
	if err := os.WriteFile(filepath.Join(dir, "cloudflared.exe"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := runHeld(t, exe)
	defer stop()

	moved, err := removeProgramFolder(dir, testRemovedSDDL(t))
	if err != nil {
		t.Fatalf("removeProgramFolder: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the program folder is still there (%v)", err)
	}
	if len(moved) != 1 || filepath.Base(moved[0]) != "soireehost.exe" {
		t.Fatalf("moved = %v, want only the running program", moved)
	}
	removed := filepath.Dir(moved[0])
	if filepath.Dir(removed) != parent || !strings.HasPrefix(filepath.Base(removed), "SoireeHost.removed-") {
		t.Fatalf("files in use went to %s", removed)
	}
	if left := leftovers(t, parent); len(left) != 1 {
		t.Fatalf("left beside the program folder: %v", left)
	}
	if left := leftovers(t, removed); len(left) != 1 {
		t.Fatalf("in the restart folder: %v (cloudflared.exe was not in use)", left)
	}
	stop()
	// on a real uninstall the restart deletes these; here the test does
	if err := os.RemoveAll(removed); err != nil {
		t.Fatalf("cleaning up: %v", err)
	}
}

// runHeld starts exe, a copy of this test binary, running
// TestSelfRemoveHelper, which keeps it running until stop is called. It
// fails the test if the running file can still be deleted.
func runHeld(t *testing.T, exe string) (stop func()) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestSelfRemoveHelper$") // #nosec G204 -- this test's own binary
	cmd.Env = append(os.Environ(), "SOIREEHOST_SELFREMOVE_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			_ = stdin.Close()
			_ = cmd.Wait()
		}
	}
	if err := os.Remove(exe); err == nil {
		stop()
		t.Fatal("a running program was deleted outright; the test proves nothing")
	}
	return stop
}

// TestReplaceProgramWhileRunning: an upgrade by "setup install" replaces
// the installed program while a control panel still runs from it (the tray
// starts at sign-in). Windows refuses to replace a running program, so the
// old one moves aside and the new one takes its name (review finding of
// 20 Nov 2026).
func TestReplaceProgramWhileRunning(t *testing.T) {
	if os.Getenv("SOIREEHOST_SELFREMOVE_HELPER") == "1" {
		t.Skip("helper run")
	}
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "soireehost.exe")
	copyFile(t, self, exe)
	stop := runHeld(t, exe)
	defer stop()
	newer := filepath.Join(dir, "soireehost.exe.new")
	if err := os.WriteFile(newer, []byte("the new program"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveFile(newer, exe); err == nil {
		t.Fatal("a running program was replaced outright; the test proves nothing")
	}
	if err := replaceProgram(newer, exe); err != nil {
		t.Fatalf("replaceProgram: %v", err)
	}
	if b, err := os.ReadFile(exe); err != nil || string(b) != "the new program" { //nolint:gosec // G304: the test's own folder
		t.Fatalf("the installed program is %q (%v), want the new one", b, err)
	}
	if exists(newer) {
		t.Fatal("the new program is still at its staging name")
	}
	var aside []string
	for _, n := range leftovers(t, dir) {
		if strings.HasPrefix(n, "soireehost.exe.old-") {
			aside = append(aside, n)
		}
	}
	if len(aside) != 1 {
		t.Fatalf("files beside the program: %v, want one moved-aside old program", leftovers(t, dir))
	}
	stop()
	// on a real install the restart deletes it; here the test does
	if err := os.Remove(filepath.Join(dir, aside[0])); err != nil {
		t.Fatalf("cleaning up: %v", err)
	}
	// with nothing running, a plain replace is used and nothing is left
	if err := os.WriteFile(newer, []byte("again"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceProgram(newer, exe); err != nil || len(leftovers(t, dir)) != 1 {
		t.Fatalf("replaceProgram with nothing running: %v, left %v", err, leftovers(t, dir))
	}
}

// TestSelfRemoveHelper is the running program of the tests above.
func TestSelfRemoveHelper(t *testing.T) {
	if os.Getenv("SOIREEHOST_SELFREMOVE_HELPER") != "1" {
		t.Skip("run by TestRemoveProgramFolderWhileRunning")
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src) //nolint:gosec // G304: this test's own binary
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o700); err != nil { //nolint:gosec // G306: a program the test runs
		t.Fatal(err)
	}
}
