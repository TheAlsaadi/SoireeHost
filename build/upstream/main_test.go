package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, tt := range []struct {
		latest, current string
		want            bool
	}{
		{"2026.12.0", "2026.11.0", true},
		{"2026.11.0", "2026.11.0", false},
		{"2026.10.7", "2026.11.0", false},
		{"4.31.0", "4.30.0", true},
		{"1.28.0-rc.1", "1.27.4", false},
		{"v4.31.0", "4.30.0", false},
		{"", "1.0.0", false},
	} {
		if got := newer(tt.latest, tt.current); got != tt.want {
			t.Errorf("newer(%q, %q) = %v", tt.latest, tt.current, got)
		}
	}
}

const sumA = "d5c1d82031da6253dcdcff64c944cd0fe063016edeb2e4fd088075fc9bd52d0a"
const sumB = "1111111111111111111111111111111111111111111111111111111111111111"

func TestNotesHashAndAgree(t *testing.T) {
	body := "### SHA256 Checksums:\n```\ncloudflared-amd64.pkg: " + sumB + "\ncloudflared-windows-amd64.exe: " + strings.ToUpper(sumA) + "\n```\n"
	got, err := notesHash(body)
	if err != nil || got != sumA {
		t.Fatalf("notesHash = %q, %v", got, err)
	}
	if _, err := notesHash(body + "cloudflared-windows-amd64.exe: " + sumB + "\n"); err == nil {
		t.Fatal("accepted notes that list the file twice")
	}
	if _, err := notesHash("nothing here"); err == nil {
		t.Fatal("accepted notes with no hash")
	}
	if err := agree(sumA, "sha256:"+sumA, sumA); err != nil {
		t.Fatalf("agree on equal hashes: %v", err)
	}
	for _, c := range [][3]string{{sumB, "sha256:" + sumA, sumA}, {sumA, "sha256:" + sumB, sumA}, {sumA, "sha256:" + sumA, sumB}, {sumA, sumA, sumA}, {sumA, "", sumA}} {
		if err := agree(c[0], c[1], c[2]); err == nil {
			t.Errorf("agree(%v) accepted a disagreement", c)
		}
	}
}

// TestEditsOnRepositoryFiles runs each edit on the real files, so a change
// in their layout breaks this test, not a scheduled run.
func TestEditsOnRepositoryFiles(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile("../../" + p) //nolint:gosec // G304: fixed repository files
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	lock, err := setCloudflaredLock(read(cloudflaredLock), "2026.12.0", sumB, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version=2026.12.0\n", "sha256=" + sumB + "\n", "releases/tag/2026.12.0\n", "release notes on 2026-12-01,"} {
		if !strings.Contains(lock, want) {
			t.Errorf("cloudflared.lock lacks %q:\n%s", want, lock)
		}
	}
	pin, err := setPin(read(pinGo), "2026.12.0", sumB)
	if err != nil || !strings.Contains(pin, `CloudflaredVersion = "2026.12.0"`) || !strings.Contains(pin, `CloudflaredSHA256  = "`+sumB+`"`) {
		t.Fatalf("pin.go: %v\n%s", err, pin)
	}
	crs, err := setCRSLock(read(crsLock), "4.31.0", "https://example.invalid/coreruleset-4.31.0-minimal.tar.gz", sumB)
	if err != nil || !strings.Contains(crs, "version=4.31.0\n") || !strings.Contains(crs, "sha256="+sumB+"\n") || !strings.Contains(crs, "releases/tag/v4.31.0\n") {
		t.Fatalf("crs.lock: %v\n%s", err, crs)
	}
	if strings.Count(crs, "file=") != strings.Count(read(crsLock), "file=") {
		t.Fatal("the file list changed")
	}
	cg, err := setCRSGo(read(crsGo), "4.31.0")
	if err != nil || !strings.Contains(cg, `const CRSVersion = "4.31.0"`) || !strings.Contains(cg, `const crsSetupVersion = "4310"`) {
		t.Fatalf("crs.go: %v", err)
	}
	mod, err := setGoLine(read(goMod), "1.27.5")
	if err != nil || goLine(mod) != "1.27.5" {
		t.Fatalf("go.mod: %v, go line %q", err, goLine(mod))
	}
	if goLine(read(goMod)) == "" {
		t.Fatal("no go line found in go.mod")
	}
	// only the version changes: every other line, blank ones included, stays
	if want := strings.Replace(read(goMod), "go "+goLine(read(goMod)), "go 1.27.5", 1); mod != want {
		t.Fatalf("setGoLine changed more than the go line:\n%s", mod)
	}
	for _, in := range []string{"module m\n\ngo 1.27.4\n\nrequire x v1.0.0\n", "module m\r\n\r\ngo 1.27.4\r\n\r\nrequire x v1.0.0\r\n"} {
		out, err := setGoLine(in, "1.27.5")
		if err != nil || out != strings.Replace(in, "go 1.27.4", "go 1.27.5", 1) {
			t.Fatalf("setGoLine(%q) = %q, %v", in, out, err)
		}
	}
}

func TestCRSSetupVersion(t *testing.T) {
	for v, want := range map[string]string{"4.30.0": "4300", "4.31.2": "4312", "4.9.0": "4090", "5.0.1": "5001"} {
		s, err := setCRSGo("const CRSVersion = \"x\"\nconst crsSetupVersion = \"1\"\n", v)
		if err != nil || !strings.Contains(s, `crsSetupVersion = "`+want+`"`) {
			t.Errorf("%s: %v %q", v, err, s)
		}
	}
	if _, err := setCRSGo("const CRSVersion = \"x\"\nconst crsSetupVersion = \"1\"\n", "4.100.0"); err == nil {
		t.Error("accepted a minor version that does not fit")
	}
}

func TestDownloadOnlyFromTheRepository(t *testing.T) {
	for _, u := range []string{"https://evil.example/x", "https://github.com/someone/cloudflared/releases/download/1/x", "http://github.com/cloudflare/cloudflared/releases/download/1/x"} {
		if _, err := download(u, "cloudflare/cloudflared", t.TempDir()+"/x"); err == nil {
			t.Errorf("download accepted %s", u)
		}
	}
}

func TestRunRefusesBadArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"apply"}, {"apply", "cloudflared", "latest"}, {"apply", "crs", "4.31.0"}, {"apply", "go", "1.27.5-rc.1"}, {"apply", "caddy", "2.12.0"}} {
		if err := run(args, os.Stdout); err == nil {
			t.Errorf("run(%v) accepted", args)
		}
	}
}
