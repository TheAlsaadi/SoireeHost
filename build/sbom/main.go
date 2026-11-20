// Command sbom writes a CycloneDX 1.6 software bill of materials for a
// built soireehost.exe (S-73, ADR-0004). It reads the module list Go
// records in every binary (debug/buildinfo), so it lists exactly what was
// compiled in, and adds the two embedded parts that are not Go modules,
// cloudflared and the Core Rule Set, from their lock files. It needs no
// tool beyond the standard library. The frontend's packages get their own
// SBOM from npm's built-in "npm sbom".
//
//	go run ./build/sbom -exe bin/soireehost.exe -version 1.3.0 -time 2026-12-01T10:00:00Z -out dist/soireehost.cdx.json
//
// The version is a flag because release builds use -trimpath, and Go then
// does not record the link flags that set it.
package main

import (
	"bufio"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	exe := fs.String("exe", "", "the built soireehost.exe")
	ver := fs.String("version", "", "the release version, without v")
	out := fs.String("out", "", "where to write the SBOM")
	stamp := fs.String("time", "", "the SBOM's timestamp, RFC 3339 (default: now)")
	cfLock := fs.String("cloudflared-lock", "build/cloudflared.lock", "")
	crsLock := fs.String("crs-lock", "build/crs.lock", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exe == "" || *out == "" {
		return errors.New("-exe, -version and -out are required")
	}
	if !version.Valid(*ver) {
		return fmt.Errorf("-version %q is not a valid version", *ver)
	}
	t := time.Now().UTC()
	if *stamp != "" {
		var err error
		if t, err = time.Parse(time.RFC3339, *stamp); err != nil {
			return fmt.Errorf("-time: %w", err)
		}
	}
	b, err := build(*exe, *ver, *cfLock, *crsLock, t)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644) // #nosec G306 G703 -- a public release file at the workflow's own -out path
}

// CycloneDX 1.6, the parts this SBOM uses.
type (
	bom struct {
		BOMFormat    string      `json:"bomFormat"`
		SpecVersion  string      `json:"specVersion"`
		SerialNumber string      `json:"serialNumber"`
		Version      int         `json:"version"`
		Metadata     metadata    `json:"metadata"`
		Components   []component `json:"components"`
	}
	metadata struct {
		Timestamp string    `json:"timestamp"`
		Component component `json:"component"`
	}
	component struct {
		Type    string `json:"type"`
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl,omitempty"`
		Hashes  []hash `json:"hashes,omitempty"`
	}
	hash struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	}
)

func build(exe, ver, cfLock, crsLock string, t time.Time) ([]byte, error) {
	f, err := os.Open(exe) // #nosec G304 G703 -- the build output named by the workflow
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return nil, err
	}
	exeHash := sum.Sum(nil)
	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		return nil, fmt.Errorf("reading the module list from %s: %w", exe, err)
	}
	app := component{
		Type: "application", Name: "soireehost", Version: ver,
		PURL:   "pkg:golang/" + bi.Main.Path + "@v" + ver,
		Hashes: []hash{{Alg: "SHA-256", Content: hex.EncodeToString(exeHash)}},
	}
	app.BOMRef = app.PURL
	var comps []component
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		c := component{Type: "library", Name: m.Path, Version: m.Version, PURL: "pkg:golang/" + m.Path + "@" + m.Version}
		c.BOMRef = c.PURL
		if h, ok := h1Hex(m.Sum); ok {
			c.Hashes = []hash{{Alg: "SHA-256", Content: h}}
		}
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	cf, err := readLock(cfLock)
	if err != nil {
		return nil, err
	}
	crs, err := readLock(crsLock)
	if err != nil {
		return nil, err
	}
	for _, c := range []component{
		{Type: "application", Name: "cloudflared", Version: cf["version"], PURL: "pkg:github/cloudflare/cloudflared@" + cf["version"],
			Hashes: []hash{{Alg: "SHA-256", Content: cf["sha256"]}}},
		{Type: "data", Name: "coreruleset", Version: crs["version"], PURL: "pkg:github/coreruleset/coreruleset@v" + crs["version"],
			Hashes: []hash{{Alg: "SHA-256", Content: crs["sha256"]}}},
	} {
		if c.Version == "" || len(c.Hashes[0].Content) != 64 {
			return nil, fmt.Errorf("lock file for %s has no version or SHA-256", c.Name)
		}
		c.BOMRef = c.PURL
		comps = append(comps, c)
	}
	doc := bom{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		// derived from the executable, so the same binary always gets the
		// same serial number
		SerialNumber: "urn:uuid:" + uuidFrom(exeHash),
		Metadata:     metadata{Timestamp: t.UTC().Format(time.RFC3339), Component: app},
		Components:   comps,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// h1Hex turns a go.sum "h1:" hash (base64 SHA-256 of the module's file
// list) into hex, as CycloneDX writes hashes.
func h1Hex(sum string) (string, bool) {
	b64, ok := strings.CutPrefix(sum, "h1:")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != sha256.Size {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// uuidFrom makes a version-4-shaped UUID from the first 16 bytes of h.
func uuidFrom(h []byte) string {
	var u [16]byte
	copy(u[:], h)
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	x := hex.EncodeToString(u[:])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// readLock reads the key=value lines of a lock file; a key that appears
// several times (crs.lock's file=) keeps its first value.
func readLock(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- a repository file
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			if _, seen := out[k]; !seen {
				out[k] = v
			}
		}
	}
	return out, sc.Err()
}
