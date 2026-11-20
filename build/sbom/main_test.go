package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSBOMOfTestBinary builds the SBOM of this test binary, which carries
// Go's module list like any other, and checks its shape: the CycloneDX
// header, the embedded components from the real lock files, and a stable
// serial number.
func TestSBOMOfTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cf, crs := filepath.Join("..", "cloudflared.lock"), filepath.Join("..", "crs.lock")
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	a, err := build(exe, "1.3.0", cf, crs, at)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b, err := build(exe, "1.3.0", cf, crs, at)
	if err != nil || string(a) != string(b) {
		t.Fatal("the same binary gave two different SBOMs")
	}
	var doc bom
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || doc.Metadata.Timestamp != "2026-12-01T10:00:00Z" {
		t.Fatalf("header: %+v", doc)
	}
	names := map[string]component{}
	for _, c := range doc.Components {
		names[c.Name] = c
	}
	if c := names["cloudflared"]; c.Version == "" || c.Hashes[0].Content == "" {
		t.Errorf("cloudflared component: %+v", c)
	}
	if c := names["coreruleset"]; c.Type != "data" || c.Version == "" {
		t.Errorf("coreruleset component: %+v", c)
	}
	if c := doc.Metadata.Component; c.Version != "1.3.0" || !strings.HasSuffix(c.PURL, "@v1.3.0") || len(c.Hashes) != 1 {
		t.Errorf("app component: %+v", c)
	}
}

// TestSBOMRefusesBadVersion: the version comes from the workflow and must
// be one the app itself accepts.
func TestSBOMRefusesBadVersion(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "v1.3.0", "latest"} {
		if err := run([]string{"-exe", exe, "-version", v, "-out", filepath.Join(t.TempDir(), "x.json")}); err == nil {
			t.Errorf("accepted -version %q", v)
		}
	}
}

func TestHelpers(t *testing.T) {
	if h, ok := h1Hex("h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="); !ok || len(h) != 64 {
		t.Errorf("h1Hex = %q, %v", h, ok)
	}
	for _, bad := range []string{"", "h1:", "h1:!!", "h2:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "h1:AAAA"} {
		if _, ok := h1Hex(bad); ok {
			t.Errorf("h1Hex accepted %q", bad)
		}
	}
	u := uuidFrom(make([]byte, 32))
	if len(u) != 36 || u[14] != '4' {
		t.Errorf("uuidFrom = %s", u)
	}
}
