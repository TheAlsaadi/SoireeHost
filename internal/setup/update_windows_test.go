package setup

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

// S-63: a rollback restores only the copy kept by this update. A stale
// .previous from an earlier update leaves the files as they are.
func TestRestoreFilesChecksKeptCopy(t *testing.T) {
	l := Layout{ProgramDir: t.TempDir()}
	writeFile(t, l.Exe(), "running")
	writeFile(t, l.Exe()+prevSuffix, "version before last")
	writeFile(t, l.Cloudflared(), "cf")
	running, err := fileHash(l.Exe())
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreFiles(l, running); err == nil {
		t.Fatal("a stale kept copy was accepted")
	}
	if readFile(t, l.Exe()) != "running" || readFile(t, l.Exe()+prevSuffix) != "version before last" || readFile(t, l.Cloudflared()) != "cf" {
		t.Fatal("files moved although the kept copy was not this update's")
	}

	// the kept copy is the version that was running: it goes back
	writeFile(t, l.Exe()+prevSuffix, "running")
	writeFile(t, l.Exe(), "new")
	if err := restoreFiles(l, running); err != nil {
		t.Fatal(err)
	}
	if readFile(t, l.Exe()) != "running" || readFile(t, l.Exe()+prevSuffix) != "<missing>" {
		t.Fatalf("not restored: %q", readFile(t, l.Exe()))
	}
}

// S-63: a .previous that can be neither deleted nor moved stops the update
// before the journal is written.
func TestRemovePreviousFailsOnLockedCopy(t *testing.T) {
	l := Layout{ProgramDir: t.TempDir()}
	prev := l.Exe() + prevSuffix
	writeFile(t, prev, "old")
	writeFile(t, l.Cloudflared()+prevSuffix, "old cf")
	p, err := windows.UTF16PtrFromString(prev)
	if err != nil {
		t.Fatal(err)
	}
	// held open with no sharing: it can be neither deleted nor renamed
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := removePrevious(l); err == nil {
		t.Fatal("a locked kept copy was ignored")
	}
	if err := windows.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	if err := removePrevious(l); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{prev, l.Cloudflared() + prevSuffix} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s still there", filepath.Base(f))
		}
	}
}
