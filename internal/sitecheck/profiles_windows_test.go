package sitecheck

// Regression tests for R-09 (docs/reviews/2026-11-12-skills-review.md): a
// user profile stored outside the Users folder, and any folder containing
// one, cannot be published, and no request path may go through AppData.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDefaultLocationsListsProfiles(t *testing.T) {
	loc, err := DefaultLocations()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	canon, err := Canonical(home)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(loc.Profiles, func(p string) bool { return strings.EqualFold(p, canon) }) {
		t.Fatalf("own profile %s missing from %v", canon, loc.Profiles)
	}
}

func TestCheckRootRefusesProfileOutsideUsers(t *testing.T) {
	loc, err := DefaultLocations()
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(wd, "testsite-profile-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	profile := filepath.Join(base, "Profiles", "bob")
	if err := os.MkdirAll(filepath.Join(profile, "Documents", "site"), 0o700); err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(profile)
	if err != nil {
		t.Fatal(err)
	}
	// as if Windows listed this folder in ProfileList
	loc.Profiles = append(loc.Profiles, canon)
	for _, root := range []string{profile, filepath.Dir(profile)} {
		if got, err := CheckRoot(root, loc); err == nil {
			t.Errorf("%s accepted as a site folder (%s)", root, got)
		}
	}
	if _, err := CheckRoot(filepath.Join(profile, "Documents", "site"), loc); err != nil {
		t.Errorf("a folder inside the profile was refused: %v", err)
	}
}

func TestStaticRefusesAppData(t *testing.T) {
	for _, p := range []string{"/AppData/Roaming/x/logins.json", "/site/appdata/x", "/NTUSER.DAT"} {
		if v := CheckStatic(p, p); v == Allow {
			t.Errorf("%s allowed", p)
		}
	}
}
