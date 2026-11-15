package sitecheck

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

func plant(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pemKey is built from pieces so no key-shaped text sits in the repository
// (the secret scanner would rightly flag it).
var pemKey = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + "PRIVATE KEY-----\n"

// Phase 4 check: the exposure check flags a planted .env file and private
// key (ADR-0008).
func TestScanExposureFlagsSecrets(t *testing.T) {
	base := testutil.SiteDir(t)
	root := filepath.Join(base, "site")
	plant(t, root, "index.html", "<h1>hi</h1>")
	plant(t, root, "css/site.css", "body{}")
	plant(t, root, ".env", "DB_PASSWORD=x")
	plant(t, root, "config/.env.production", "X=1")
	plant(t, root, "server.key", pemKey)
	plant(t, root, "keys/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	plant(t, root, ".git/config", "[core]")
	plant(t, root, "notes.txt", "my notes\n"+pemKey)
	plant(t, root, "deploy/putty.txt", "PuTTY-User-Key-File-3: ssh-ed25519\n")
	plant(t, root, "vault.dat", string([]byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 2}))
	plant(t, root, "app/prod.env", "SECRET=1")
	plant(t, root, "about/readme.md", "the word PRIVATE KEY in prose without the PEM dashes")
	testutil.Junction(t, filepath.Join(root, "escape"), filepath.Join(base, "outside"))
	plant(t, base, "outside/leaked.txt", pemKey)

	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read-only
	rep := ScanExposure(r, Rules{}, time.Minute)
	if err := ValidateExposureReport(rep); err != nil {
		t.Fatalf("report does not validate: %v", err)
	}
	got := map[string]Finding{}
	for _, f := range rep.Findings {
		got[f.Path] = f
	}
	want := map[string]Finding{
		".env":                   {Path: ".env", Kind: KindBlockedName},
		"config/.env.production": {Path: "config/.env.production", Kind: KindBlockedName},
		"server.key":             {Path: "server.key", Kind: KindBlockedName},
		"keys/id_rsa":            {Path: "keys/id_rsa", Kind: KindBlockedName},
		".git":                   {Path: ".git", Kind: KindBlockedName},
		"notes.txt":              {Path: "notes.txt", Kind: KindPrivateKey, Served: true},
		"deploy/putty.txt":       {Path: "deploy/putty.txt", Kind: KindPrivateKey, Served: true},
		"vault.dat":              {Path: "vault.dat", Kind: KindPrivateKey, Served: true},
		"app/prod.env":           {Path: "app/prod.env", Kind: KindEnvFile, Served: true},
	}
	for p, w := range want {
		if g, ok := got[p]; !ok || g != w {
			t.Errorf("%s: got %+v, want %+v", p, g, w)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected finding %q", p)
		}
		if strings.Contains(p, "leaked") || strings.HasPrefix(p, "escape") {
			t.Errorf("the scan followed a junction out of the folder: %q", p)
		}
	}
	if served := rep.Served(); len(served) != 4 {
		t.Errorf("served findings = %+v", served)
	}
	if rep.Incomplete {
		t.Error("a small folder was reported incomplete")
	}
}

func TestScanExposureWellKnown(t *testing.T) {
	root := filepath.Join(testutil.SiteDir(t), "site")
	plant(t, root, ".well-known/security.txt", "Contact: x")
	plant(t, root, ".well-known/acme.txt", pemKey)
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read-only
	off := ScanExposure(r, Rules{}, time.Minute)
	if len(off.Findings) != 1 || off.Findings[0].Path != ".well-known" || off.Findings[0].Served {
		t.Fatalf("without the opt-in: %+v", off.Findings)
	}
	on := ScanExposure(r, Rules{AllowWellKnown: true}, time.Minute)
	if len(on.Findings) != 1 || on.Findings[0].Path != ".well-known/acme.txt" || !on.Findings[0].Served {
		t.Fatalf("with the opt-in: %+v", on.Findings)
	}
}

func TestScanExposureStopsAtLimits(t *testing.T) {
	root := filepath.Join(testutil.SiteDir(t), "site")
	for i := range 3 {
		plant(t, root, "d/"+strings.Repeat("x", i+1)+".txt", "x")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read-only
	if rep := ScanExposure(r, Rules{}, -time.Second); !rep.Incomplete {
		t.Fatal("an expired deadline did not mark the report incomplete")
	}
}

func TestValidateExposureReport(t *testing.T) {
	ok := ExposureReport{Findings: []Finding{{Path: "a/b.txt", Kind: KindPrivateKey, Served: true}}}
	if err := ValidateExposureReport(ok); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]Finding{
		"absolute":       {Path: "/etc/x", Kind: KindPrivateKey, Served: true},
		"traversal":      {Path: "a/../b", Kind: KindPrivateKey, Served: true},
		"backslash":      {Path: `a\b`, Kind: KindPrivateKey, Served: true},
		"drive":          {Path: "C:x", Kind: KindPrivateKey, Served: true},
		"control":        {Path: "a\x1bb", Kind: KindPrivateKey, Served: true},
		"bidi":           {Path: "a" + string(rune(0x202e)) + "b", Kind: KindPrivateKey, Served: true},
		"unknown kind":   {Path: "a", Kind: "virus", Served: true},
		"served blocked": {Path: ".env", Kind: KindBlockedName, Served: true},
		"unserved key":   {Path: "a", Kind: KindPrivateKey},
		"empty segment":  {Path: "a//b", Kind: KindPrivateKey, Served: true},
		"too long":       {Path: strings.Repeat("a", MaxFindingPath+1), Kind: KindPrivateKey, Served: true},
	} {
		if err := ValidateExposureReport(ExposureReport{Findings: []Finding{f}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := ValidateExposureReport(ExposureReport{}); err == nil {
		t.Error("nil finding list accepted")
	}
	if err := ValidateExposureReport(ExposureReport{Findings: slices.Repeat([]Finding{ok.Findings[0]}, MaxFindings+1)}); err == nil {
		t.Error("too many findings accepted")
	}
}

// SE-24: a Locations value with an empty required field is refused instead
// of switching that S-11 rule off.
func TestEmptyLocationsRefused(t *testing.T) {
	loc, base := fakeLocations(t)
	dir := filepath.Join(base, "Sites", "blog")
	for name, mutate := range map[string]func(*Locations){
		"zero":          func(l *Locations) { *l = Locations{} },
		"windows":       func(l *Locations) { l.Windows = "" },
		"program files": func(l *Locations) { l.ProgramFiles = nil },
		"empty pf":      func(l *Locations) { l.ProgramFiles = []string{l.ProgramFiles[0], ""} },
		"programdata":   func(l *Locations) { l.ProgramData = "" },
		"users":         func(l *Locations) { l.UserProfiles = "" },
	} {
		l := loc
		l.ProgramFiles = slices.Clone(loc.ProgramFiles)
		mutate(&l)
		if _, err := CheckRoot(dir, l); err == nil {
			t.Errorf("%s: CheckRoot accepted", name)
		}
		if r, err := OpenRoot(dir, l); err == nil {
			_ = r.Close()
			t.Errorf("%s: OpenRoot accepted", name)
		}
	}
	if _, err := CheckRoot(dir, loc); err != nil {
		t.Fatalf("full locations refused: %v", err)
	}
}
