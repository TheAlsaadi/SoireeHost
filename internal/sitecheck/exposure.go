package sitecheck

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// Exposure finding kinds, a closed set (ADR-0008).
const (
	// KindBlockedName is a name the path rules never serve (S-12): listed so
	// the user can move it, but not reachable.
	KindBlockedName = "blocked_name"
	// KindPrivateKey is a file that would be served and starts like a
	// private key or a password database.
	KindPrivateKey = "private_key"
	// KindEnvFile is a file that would be served and is named like an
	// environment file holding settings and secrets (app.env, prod.env).
	KindEnvFile = "env_file"
)

// ExposureKinds lists every kind.
var ExposureKinds = []string{KindBlockedName, KindPrivateKey, KindEnvFile}

// Scan limits.
const (
	MaxScanEntries  = 50_000
	MaxScanDepth    = 32
	MaxFindings     = 200
	MaxFindingPath  = 1024
	scanHeadBytes   = 4 << 10
	DefaultScanTime = 30 * time.Second
)

// Finding is one risky file or folder in a site folder. Path is relative,
// with '/' separators; it is a name from the user's own folder and is shown
// as text only (S-34).
type Finding struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Served bool   `json:"served"`
}

// ExposureReport is the result of a scan. Incomplete means a limit stopped
// the scan before it saw everything.
type ExposureReport struct {
	Findings   []Finding `json:"findings"`
	Entries    int       `json:"entries"`
	Incomplete bool      `json:"incomplete"`
}

// Served lists the findings that would be served.
func (r ExposureReport) Served() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Served {
			out = append(out, f)
		}
	}
	return out
}

// ScanExposure walks an opened site folder and reports what it would expose
// (ADR-0008). It never follows a link or junction and never leaves the
// folder: root is an os.Root. Names are judged by the same rules that decide
// what a static site serves; files that would be served are read for their
// first 4 KiB and reported if they start like a key. It stops at the limits
// above or after timeout, and marks the report incomplete.
func ScanExposure(root *os.Root, rules Rules, timeout time.Duration) ExposureReport {
	s := scanner{root: root, rules: rules, deadline: time.Now().Add(timeout)}
	s.walk(".", 0)
	if s.rep.Findings == nil {
		s.rep.Findings = []Finding{}
	}
	return s.rep
}

// Findings are capped per kind, so names that are never served cannot use up
// the report and stop the walk before a served secret is found
// (sharp-edges finding SE7-2). Never-served names past their cap are left
// out of the list; the walk goes on.
const (
	maxBlockedFindings = MaxFindings / 2
	maxServedFindings  = MaxFindings - maxBlockedFindings
)

type scanner struct {
	root            *os.Root
	rules           Rules
	deadline        time.Time
	rep             ExposureReport
	served, blocked int
}

func (s *scanner) stop() bool {
	if s.rep.Entries >= MaxScanEntries || s.served >= maxServedFindings || time.Now().After(s.deadline) {
		s.rep.Incomplete = true
		return true
	}
	return false
}

func (s *scanner) add(rel, kind string, served bool) {
	// a path the supervisor would refuse (too long, control or bidi
	// characters) is left out, and the report says it is incomplete
	if validFindingPath(rel) != nil {
		s.rep.Incomplete = true
		return
	}
	if served {
		s.served++
	} else {
		if s.blocked >= maxBlockedFindings {
			return
		}
		s.blocked++
	}
	s.rep.Findings = append(s.rep.Findings, Finding{Path: rel, Kind: kind, Served: served})
}

func (s *scanner) walk(dir string, depth int) {
	if depth > MaxScanDepth {
		s.rep.Incomplete = true
		return
	}
	f, err := s.root.Open(dir)
	if err != nil {
		return
	}
	ents, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return
	}
	for _, e := range ents {
		if s.stop() {
			return
		}
		s.rep.Entries++
		rel := e.Name()
		if dir != "." {
			rel = dir + "/" + e.Name()
		}
		t := e.Type()
		// links, junctions and devices are never served (RootFS hides them)
		if t&(fs.ModeSymlink|fs.ModeIrregular|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket) != 0 {
			continue
		}
		if !s.servable(rel) {
			// list only the S-12 never-serve names; other refusals (odd
			// characters, short-name shapes) are not exposure risks
			if hiddenOrBlocked(e.Name()) {
				s.add(rel, KindBlockedName, false)
			}
			continue // nothing under a refused folder is served either
		}
		if e.IsDir() {
			s.walk(rel, depth+1)
			continue
		}
		if !t.IsRegular() {
			continue
		}
		if kind := s.sniff(rel, e.Name()); kind != "" {
			s.add(rel, kind, true)
		}
	}
}

// servable reports whether a request for rel would pass the static path
// rules, as the browser would send it (each segment percent-encoded).
func (s *scanner) servable(rel string) bool {
	return s.rules.Static(NamePath(rel)) == Allow
}

// keyMarkers are byte strings that start a private key or a password store.
var keyMarkers = [][]byte{
	[]byte("PRIVATE KEY-----"), // PEM: RSA, EC, DSA, ENCRYPTED, OPENSSH, PGP ... PRIVATE KEY
	[]byte("PuTTY-User-Key-File-"),
}

// keepassMagic are the KeePass 1 and 2 file signatures.
var keepassMagic = [][]byte{
	{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5},
	{0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5},
}

func (s *scanner) sniff(rel, name string) string {
	if strings.EqualFold(path.Ext(name), ".env") {
		return KindEnvFile
	}
	f, err := s.root.Open(rel)
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck // read-only
	head := make([]byte, scanHeadBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return ""
	}
	head = head[:n]
	for _, m := range keepassMagic {
		if bytes.HasPrefix(head, m) {
			return KindPrivateKey
		}
	}
	for _, m := range keyMarkers {
		if bytes.Contains(head, m) {
			return KindPrivateKey
		}
	}
	return ""
}

// ValidateExposureReport checks a report as it arrives from the web worker
// (SE-21 style): closed kinds, relative clean paths, counts in range.
func ValidateExposureReport(r ExposureReport) error {
	if r.Findings == nil || len(r.Findings) > MaxFindings {
		return errors.New("bad finding list")
	}
	if r.Entries < 0 || r.Entries > MaxScanEntries {
		return errors.New("entry count out of range")
	}
	for _, f := range r.Findings {
		if !validKind(f.Kind) {
			return errors.New("unknown finding kind")
		}
		if (f.Kind == KindBlockedName) == f.Served {
			return errors.New("a blocked name is never served, and a served finding is never a blocked name")
		}
		if err := validFindingPath(f.Path); err != nil {
			return err
		}
	}
	return nil
}

func validKind(k string) bool {
	return slices.Contains(ExposureKinds, k)
}

func validFindingPath(p string) error {
	if p == "" || len(p) > MaxFindingPath || strings.ToValidUTF8(p, "") != p {
		return errors.New("bad finding path")
	}
	if strings.HasPrefix(p, "/") || strings.ContainsAny(p, `\:`) {
		return errors.New("finding path is not relative")
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("finding path is not clean")
		}
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x202d {
			return errors.New("finding path holds a control character")
		}
	}
	return nil
}
