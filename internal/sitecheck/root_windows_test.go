package sitecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

// fakeLocations builds a Locations whose folders live under a temp dir, so the
// tests exercise every rule without touching the real Windows folders.
func fakeLocations(t *testing.T) (Locations, string) {
	t.Helper()
	base := mustCanonical(t, testutil.SiteDir(t))
	mk := func(p ...string) string {
		d := filepath.Join(append([]string{base}, p...)...)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		return d
	}
	loc := Locations{
		Windows:      mk("Windows"),
		ProgramFiles: []string{mk("Program Files"), mk("Program Files (x86)")},
		ProgramData:  mk("ProgramData"),
		UserProfiles: mk("Users"),
	}
	mk("Users", "alice", "Documents", "site")
	mk("Sites", "blog")
	return loc, base
}

func mustCanonical(t *testing.T, p string) string {
	t.Helper()
	c, err := Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckRootAccepts(t *testing.T) {
	loc, base := fakeLocations(t)
	for _, rel := range []string{`Sites\blog`, `Users\alice\Documents\site`} {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		got, err := CheckRoot(p, loc)
		if err != nil {
			t.Errorf("%s refused: %v", rel, err)
			continue
		}
		if !strings.EqualFold(got, p) {
			t.Errorf("canonical %q, want %q", got, p)
		}
	}
}

// S-11: blocked folders, their children and their parents are refused.
func TestCheckRootRefuses(t *testing.T) {
	loc, base := fakeLocations(t)
	refused := []string{
		`Windows`, `Windows\System32`, `Program Files`, `Program Files\App\www`, `Program Files (x86)`,
		`ProgramData\SoireeHost`, `ProgramData\SoireeHost\secrets`, `ProgramData`, `ProgramData\ssh`, `ProgramData\Other\www`,
		`Users`, `Users\alice`, ``,
	}
	for _, rel := range refused {
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckRoot(p, loc); err == nil {
			t.Errorf("%q accepted", rel)
		}
	}
}

func TestCheckRootRealSystem(t *testing.T) {
	loc, err := DefaultLocations()
	if err != nil {
		t.Fatal(err)
	}
	drive := os.Getenv("SystemDrive") + `\`
	for _, p := range []string{drive, loc.Windows, filepath.Join(loc.Windows, "System32"), loc.ProgramFiles[0], loc.UserProfiles} {
		if _, err := CheckRoot(p, loc); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if _, err := CheckRoot(home, loc); err == nil {
			t.Errorf("profile root %q accepted", home)
		}
		appdata := filepath.Join(home, "AppData")
		if _, err := os.Stat(appdata); err == nil {
			if _, err := CheckRoot(appdata, loc); err == nil {
				t.Errorf("%q accepted", appdata)
			}
		}
	}
}

func TestCheckRootNotAFolder(t *testing.T) {
	loc, base := fakeLocations(t)
	f := filepath.Join(base, "Sites", "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckRoot(f, loc); err == nil {
		t.Error("file accepted as root")
	}
	if _, err := CheckRoot(filepath.Join(base, "missing"), loc); err == nil {
		t.Error("missing folder accepted")
	}
	if _, err := CheckRoot(`\\localhost\C$\Sites`, loc); err == nil {
		t.Error("UNC path accepted")
	}
}

// S-11: a junction is resolved, so one pointing at a blocked folder is refused
// and one pointing at an allowed folder yields the target's real path.
func TestCheckRootJunction(t *testing.T) {
	loc, base := fakeLocations(t)
	bad := filepath.Join(base, "Sites", "sneaky")
	testutil.Junction(t, bad, filepath.Join(base, "Windows"))
	if _, err := CheckRoot(bad, loc); err == nil {
		t.Error("junction into Windows accepted")
	}
	if _, err := OpenRoot(bad, loc); err == nil {
		t.Error("OpenRoot followed a junction into Windows")
	}
	good := filepath.Join(base, "Sites", "alias")
	target := filepath.Join(base, "Sites", "blog")
	testutil.Junction(t, good, target)
	got, err := CheckRoot(good, loc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got, target) {
		t.Errorf("canonical %q, want %q", got, target)
	}
}

func TestOpenRoot(t *testing.T) {
	loc, base := fakeLocations(t)
	dir := filepath.Join(base, "Sites", "blog")
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(dir, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	b, err := r.ReadFile("index.html")
	if err != nil || string(b) != "hi" {
		t.Fatalf("read %q, %v", b, err)
	}
	if _, err := OpenRoot(filepath.Join(base, "Windows"), loc); err == nil {
		t.Error("OpenRoot accepted Windows")
	}
}
