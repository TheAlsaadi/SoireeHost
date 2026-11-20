// Command upstream is the S-65 upstream watcher's tool (ADR-0004). It
// compares the pinned cloudflared, Core Rule Set and Go toolchain with their
// newest stable releases, and moves a pin to a new release after checking
// it. Caddy, Coraza and every other Go module are Dependabot's (S-65).
//
//	go run ./build/upstream check
//	go run ./build/upstream apply cloudflared 2026.12.0
//	go run ./build/upstream apply crs 4.31.0 -dir C:\temp\crs
//	go run ./build/upstream apply go 1.27.5
//
// check prints one "component version" line per newer release. apply
// cloudflared accepts a release only when the SHA-256 in its release notes,
// the digest GitHub reports for the asset and the hash of the downloaded
// file all agree. apply crs downloads the archive and its signature into
// -dir for the workflow to verify with gpg, checks the archive against
// GitHub's digest, and updates the lock and the Go constants; check-crs.ps1
// -Update then replaces the vendored files.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

const (
	cloudflaredLock = "build/cloudflared.lock"
	crsLock         = "build/crs.lock"
	pinGo           = "internal/tunnel/pin.go"
	crsGo           = "internal/waf/crs.go"
	goMod           = "go.mod"
	cloudflaredExe  = "cloudflared-windows-amd64.exe"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "upstream:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "check":
		return check(out)
	case len(args) >= 3 && args[0] == "apply" && version.Release(args[2]):
		switch {
		case args[1] == "cloudflared" && len(args) == 3:
			return applyCloudflared(args[2])
		case args[1] == "crs" && len(args) == 5 && args[3] == "-dir":
			return applyCRS(args[2], args[4])
		case args[1] == "go" && len(args) == 3:
			return applyGo(args[2])
		}
	}
	return errors.New("usage: upstream check | apply cloudflared VERSION | apply crs VERSION -dir DIR | apply go VERSION")
}

// check lists every pin with a newer stable release.
func check(out io.Writer) error {
	type pin struct{ name, current, latest string }
	var pins []pin
	cf, err := readLock(cloudflaredLock)
	if err != nil {
		return err
	}
	rel, err := latestRelease("cloudflare/cloudflared")
	if err != nil {
		return err
	}
	pins = append(pins, pin{"cloudflared", cf["version"], rel.Tag})
	crs, err := readLock(crsLock)
	if err != nil {
		return err
	}
	if rel, err = latestRelease("coreruleset/coreruleset"); err != nil {
		return err
	}
	pins = append(pins, pin{"crs", crs["version"], strings.TrimPrefix(rel.Tag, "v")})
	mod, err := os.ReadFile(goMod)
	if err != nil {
		return err
	}
	goLatest, err := latestGo()
	if err != nil {
		return err
	}
	pins = append(pins, pin{"go", goLine(string(mod)), goLatest})
	for _, p := range pins {
		if newer(p.latest, p.current) {
			if _, err := fmt.Fprintf(out, "%s %s\n", p.name, p.latest); err != nil {
				return err
			}
		}
	}
	return nil
}

// newer reports whether latest is a stable release above current.
func newer(latest, current string) bool {
	if !version.Release(latest) {
		return false
	}
	c, err := version.Compare(latest, current)
	return err == nil && c > 0
}

// release is the part of GitHub's release API the watcher reads.
type release struct {
	Tag    string  `json:"tag_name"`
	Body   string  `json:"body"`
	Draft  bool    `json:"draft"`
	Pre    bool    `json:"prerelease"`
	Assets []asset `json:"assets"`
}

type asset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	URL    string `json:"browser_download_url"`
}

var client = &http.Client{Timeout: 5 * time.Minute}

// getJSON reads one of the fixed API addresses above (GitHub's release API,
// go.dev's download list).
func getJSON(url string, v any) error {
	// #nosec G704 -- fixed hosts; only the repository and a checked version vary
	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx // a short-lived command with a client timeout
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

func latestRelease(repo string) (release, error) {
	var r release
	err := getJSON("https://api.github.com/repos/"+repo+"/releases/latest", &r)
	return r, err
}

func releaseByTag(repo, tag string) (release, error) {
	var r release
	if err := getJSON("https://api.github.com/repos/"+repo+"/releases/tags/"+tag, &r); err != nil {
		return r, err
	}
	if r.Draft || r.Pre {
		return r, fmt.Errorf("%s %s is not a stable release", repo, tag)
	}
	return r, nil
}

// latestGo is the newest stable Go release, from go.dev.
func latestGo() (string, error) {
	var rs []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	if err := getJSON("https://go.dev/dl/?mode=json", &rs); err != nil {
		return "", err
	}
	for _, r := range rs {
		if v, ok := strings.CutPrefix(r.Version, "go"); ok && r.Stable && version.Release(v) {
			return v, nil
		}
	}
	return "", errors.New("go.dev lists no stable release")
}

// download fetches url into path and returns its SHA-256. The address
// comes from GitHub's API answer, so it must be a release download of the
// expected repository.
func download(url, repo, path string) (string, error) {
	if !strings.HasPrefix(url, "https://github.com/"+repo+"/releases/download/") {
		return "", fmt.Errorf("unexpected download address %q for %s", url, repo)
	}
	resp, err := client.Get(url) //nolint:noctx // a short-lived command with a client timeout
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path) // #nosec G304 G703 -- a fixed file name in the workflow's own download folder
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return hex.EncodeToString(h.Sum(nil)), err
}

func applyCloudflared(v string) error {
	r, err := releaseByTag("cloudflare/cloudflared", v)
	if err != nil {
		return err
	}
	notes, err := notesHash(r.Body)
	if err != nil {
		return err
	}
	a, err := findAsset(r, cloudflaredExe)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "cloudflared-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // a temporary folder
	got, err := download(a.URL, "cloudflare/cloudflared", filepath.Join(tmp, cloudflaredExe))
	if err != nil {
		return err
	}
	if err := agree(notes, a.Digest, got); err != nil {
		return fmt.Errorf("cloudflared %s: %w", v, err)
	}
	return editFiles(map[string]func(string) (string, error){
		cloudflaredLock: func(s string) (string, error) { return setCloudflaredLock(s, v, got, time.Now().UTC()) },
		pinGo:           func(s string) (string, error) { return setPin(s, v, got) },
	})
}

func applyCRS(v, dir string) error {
	r, err := releaseByTag("coreruleset/coreruleset", "v"+v)
	if err != nil {
		return err
	}
	name := "coreruleset-" + v + "-minimal.tar.gz"
	a, err := findAsset(r, name)
	if err != nil {
		return err
	}
	sig, err := findAsset(r, name+".asc")
	if err != nil {
		return err
	}
	got, err := download(a.URL, "coreruleset/coreruleset", filepath.Join(dir, name))
	if err != nil {
		return err
	}
	if digest, ok := strings.CutPrefix(a.Digest, "sha256:"); !ok || digest != got {
		return fmt.Errorf("CRS %s: the archive's hash %s does not match GitHub's digest %s", v, got, a.Digest)
	}
	if _, err := download(sig.URL, "coreruleset/coreruleset", filepath.Join(dir, name+".asc")); err != nil {
		return err
	}
	return editFiles(map[string]func(string) (string, error){
		crsLock: func(s string) (string, error) { return setCRSLock(s, v, a.URL, got) },
		crsGo:   func(s string) (string, error) { return setCRSGo(s, v) },
	})
}

func applyGo(v string) error {
	return editFiles(map[string]func(string) (string, error){
		goMod: func(s string) (string, error) { return setGoLine(s, v) },
	})
}

func findAsset(r release, name string) (asset, error) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, nil
		}
	}
	return asset{}, fmt.Errorf("release %s has no asset %s", r.Tag, name)
}

// editFiles applies each edit and writes every file only if all succeed.
func editFiles(edits map[string]func(string) (string, error)) error {
	out := map[string]string{}
	for path, edit := range edits {
		b, err := os.ReadFile(path) // #nosec G304 -- fixed repository files
		if err != nil {
			return err
		}
		s, err := edit(string(b))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out[path] = s
	}
	for path, s := range out {
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil { // #nosec G306 -- repository files
			return err
		}
	}
	return nil
}

// notesHash finds "cloudflared-windows-amd64.exe: <sha256>" in release
// notes.
func notesHash(body string) (string, error) {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(cloudflaredExe) + `:\s*([0-9a-fA-F]{64})\s*$`)
	m := re.FindAllStringSubmatch(body, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("the release notes list %d SHA-256 values for %s, not one", len(m), cloudflaredExe)
	}
	return strings.ToLower(m[0][1]), nil
}

// agree requires the three hashes of a download to be the same.
func agree(notes, digest, got string) error {
	d, ok := strings.CutPrefix(digest, "sha256:")
	switch {
	case !ok:
		return fmt.Errorf("GitHub reports no SHA-256 digest (%q)", digest)
	case notes != got || d != got:
		return fmt.Errorf("hashes disagree: release notes %s, GitHub digest %s, download %s", notes, d, got)
	}
	return nil
}

// readLock reads key=value lines, the first value of each key.
func readLock(path string) (map[string]string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repository files
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			if _, seen := out[k]; !seen {
				out[k] = v
			}
		}
	}
	return out, nil
}

// replaceOnce replaces the single match of re in s, or fails.
func replaceOnce(s, re, repl string) (string, error) {
	r := regexp.MustCompile(re)
	if n := len(r.FindAllStringIndex(s, -1)); n != 1 {
		return "", fmt.Errorf("expected one match of %s, found %d", re, n)
	}
	return r.ReplaceAllLiteralString(s, repl), nil
}

func setCloudflaredLock(s, v, sum string, now time.Time) (string, error) {
	var err error
	steps := []struct{ re, repl string }{
		{`(?m)^version=.*$`, "version=" + v},
		{`(?m)^sha256=.*$`, "sha256=" + sum},
		{`(?m)^# Source: .*$`, "# Source: https://github.com/cloudflare/cloudflared/releases/tag/" + v},
		{`(?m)^# SHA-256 copied from .*$`, "# SHA-256 copied from the \"SHA256 Checksums\" section of the release notes on " + now.Format("2006-01-02") + ","},
	}
	for _, st := range steps {
		if s, err = replaceOnce(s, st.re, st.repl); err != nil {
			return "", err
		}
	}
	return s, nil
}

func setPin(s, v, sum string) (string, error) {
	s, err := replaceOnce(s, `CloudflaredVersion = "[^"]*"`, `CloudflaredVersion = "`+v+`"`)
	if err != nil {
		return "", err
	}
	return replaceOnce(s, `CloudflaredSHA256  = "[0-9a-f]{64}"`, `CloudflaredSHA256  = "`+sum+`"`)
}

func setCRSLock(s, v, url, sum string) (string, error) {
	var err error
	steps := []struct{ re, repl string }{
		{`(?m)^version=.*$`, "version=" + v},
		{`(?m)^url=.*$`, "url=" + url},
		{`(?m)^sha256=.*$`, "sha256=" + sum},
		{`(?m)^# Source: .*$`, "# Source: https://github.com/coreruleset/coreruleset/releases/tag/v" + v},
	}
	for _, st := range steps {
		if s, err = replaceOnce(s, st.re, st.repl); err != nil {
			return "", err
		}
	}
	return s, nil
}

// setCRSGo sets CRSVersion and crsSetupVersion ("4.31.0" is "4310").
func setCRSGo(s, v string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || len(parts[1]) > 2 || len(parts[2]) > 1 {
		return "", fmt.Errorf("CRS version %s does not fit the setup version scheme", v)
	}
	minor := parts[1]
	if len(minor) == 1 {
		minor = "0" + minor
	}
	setup := parts[0] + minor + parts[2]
	s, err := replaceOnce(s, `const CRSVersion = "[^"]*"`, `const CRSVersion = "`+v+`"`)
	if err != nil {
		return "", err
	}
	return replaceOnce(s, `const crsSetupVersion = "[0-9]+"`, `const crsSetupVersion = "`+setup+`"`)
}

func goLine(mod string) string {
	m := regexp.MustCompile(`(?m)^go ([0-9.]+)[ \t\r]*$`).FindStringSubmatch(mod)
	if m == nil {
		return ""
	}
	return m[1]
}

func setGoLine(s, v string) (string, error) {
	// only the version itself is replaced: a pattern reaching to the end of
	// the line would also take its carriage return, or with \s the line
	// break and the blank line after it
	return replaceOnce(s, `(?m)^go [0-9.]+`, "go "+v)
}
