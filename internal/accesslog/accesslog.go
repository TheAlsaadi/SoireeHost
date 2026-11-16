// Package accesslog reads the web worker's access log for the access.list
// control method (ADR-0009). Every field of every line is attacker-influenced
// (the request) or worker-written (a compromised worker may write anything
// into its own log folder), so each line is decoded with size limits and
// every field is cleaned into a bounded shape before it leaves this package.
// The control panel still renders all of it as text only (S-34).
package accesslog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
	"github.com/TheAlsaadi/SoireeHost/internal/logread"
	"github.com/TheAlsaadi/SoireeHost/internal/redact"
)

// LogName is the access log's file name inside the web worker's log folder;
// rotated files that are not compressed are named access-<time>.log.
const LogName = "access.log"

// Limits.
const (
	MaxLineBytes   = 64 << 10
	MaxReadBytes   = 64 << 20
	MaxPage        = 500
	DefaultPage    = 200
	MaxUserAgent   = 512
	MaxReferer     = 512
	maxMethodLen   = 16
	accessLoggerNS = "http.log.access"
)

// Result classes a query can select.
const (
	ClassAll         = ""
	ClassOK          = "ok"           // 1xx to 3xx
	ClassClientError = "client_error" // 4xx
	ClassServerError = "server_error" // 5xx
	ClassBlocked     = "blocked"      // 403, then matched to a firewall block by the caller
)

// ValidClass reports whether c is one of the classes above.
func ValidClass(c string) bool {
	switch c {
	case ClassAll, ClassOK, ClassClientError, ClassServerError, ClassBlocked:
		return true
	}
	return false
}

// Entry is one request. It holds only what Activity shows: never a cookie,
// an authorization header or a query value (S-18).
type Entry struct {
	Time       time.Time `json:"time"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	URI        string    `json:"uri"`
	Status     int       `json:"status"`
	ClientIP   string    `json:"client_ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Referer    string    `json:"referer,omitempty"`
	Size       int64     `json:"size"`
	DurationMs int64     `json:"duration_ms"`
}

// Query selects entries newest first: those whose host is in Hosts (all if
// nil), of one class, newer than After and older than Before (no bound if
// zero), at most Limit.
type Query struct {
	Hosts  map[string]bool
	Class  string
	After  time.Time
	Before time.Time
	Limit  int
}

// Page is one answer.
type Page struct {
	Entries []Entry
	Skipped int
	More    bool
}

// rawLine is the part of Caddy's access-log line that is read. Unknown
// fields are ignored: Caddy adds fields between releases.
type rawLine struct {
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Request struct {
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Size     int64   `json:"size"`
	Status   int     `json:"status"`
	Duration float64 `json:"duration"`
}

// ParseLine decodes one access-log line and cleans it.
func ParseLine(b []byte) (Entry, error) {
	if len(b) > MaxLineBytes {
		return Entry{}, errors.New("line too long")
	}
	var l rawLine
	if err := json.Unmarshal(b, &l); err != nil {
		return Entry{}, fmt.Errorf("malformed line: %w", err)
	}
	if !strings.HasPrefix(l.Logger, accessLoggerNS) {
		return Entry{}, errors.New("not an access-log line")
	}
	if l.Status < 100 || l.Status > 599 {
		return Entry{}, errors.New("no valid status")
	}
	if l.TS <= 0 || l.TS > 1e11 || math.IsNaN(l.TS) {
		return Entry{}, errors.New("no valid time")
	}
	sec, frac := math.Modf(l.TS)
	e := Entry{
		Time:      time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Method:    cleanMethod(l.Request.Method),
		Host:      cleanHost(l.Request.Host),
		URI:       fwevent.CleanURI(l.Request.URI),
		Status:    l.Status,
		ClientIP:  cleanIP(l.Request.ClientIP),
		UserAgent: cleanText(header(l.Request.Headers, "User-Agent"), MaxUserAgent),
		Referer:   cleanText(redact.URI(header(l.Request.Headers, "Referer")), MaxReferer),
		Size:      max(l.Size, 0),
	}
	if d := l.Duration * 1000; d > 0 && d < math.MaxInt32 {
		e.DurationMs = int64(d)
	}
	return e, nil
}

func header(h map[string][]string, name string) string {
	if v := h[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// cleanMethod keeps a method made of token characters, upper-cased, or
// replaces it with OTHER.
func cleanMethod(m string) string {
	if m == "" || len(m) > maxMethodLen {
		return "OTHER"
	}
	for _, c := range []byte(m) {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '-' {
			return "OTHER"
		}
	}
	return strings.ToUpper(m)
}

// cleanHost keeps a valid hostname, lower-cased and without a port, or drops
// it.
func cleanHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	if config.ValidateHostname(h) != nil && h != "localhost" && h != "127.0.0.1" {
		return ""
	}
	return h
}

func cleanIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.String()
}

// cleanText makes s valid UTF-8 and cuts it to at most n bytes on a
// character boundary. Control and format characters are kept: the control
// panel shows them as visible markers, so the text is shown as it was sent.
func cleanText(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	end := n
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

func (q Query) matches(e Entry) bool {
	if q.Hosts != nil && !q.Hosts[e.Host] {
		return false
	}
	if !q.After.IsZero() && !e.Time.After(q.After) {
		return false
	}
	if !q.Before.IsZero() && !e.Time.Before(q.Before) {
		return false
	}
	switch q.Class {
	case ClassOK:
		return e.Status < 400
	case ClassClientError:
		return e.Status >= 400 && e.Status < 500
	case ClassServerError:
		return e.Status >= 500
	case ClassBlocked:
		return e.Status == 403
	}
	return true
}

// Read answers q from access.log and its uncompressed rotated files in dir,
// newest first.
func Read(dir string, q Query) (Page, error) {
	if q.Limit <= 0 || q.Limit > MaxPage {
		q.Limit = DefaultPage
	}
	files, err := logread.Files(dir, LogName, "access-", q.After)
	if err != nil {
		return Page{}, err
	}
	var page Page
	budget := int64(MaxReadBytes)
	for _, f := range files {
		if budget <= 0 {
			page.More = true
			break
		}
		entries, skipped, used, err := readFile(f, q, budget)
		if err != nil {
			return Page{}, err
		}
		budget -= used
		page.Skipped += skipped
		for _, e := range slices.Backward(entries) {
			if len(page.Entries) == q.Limit {
				page.More = true
				break
			}
			page.Entries = append(page.Entries, e)
		}
		if len(page.Entries) == q.Limit {
			page.More = true
			break
		}
	}
	if page.Entries == nil {
		page.Entries = []Entry{}
	}
	return page, nil
}

func readFile(path string, q Query, budget int64) ([]Entry, int, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a file name listed from the supervisor's own view of the web log folder
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, fmt.Errorf("opening an access log: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	lr := &io.LimitedReader{R: f, N: budget}
	r := bufio.NewReaderSize(lr, MaxLineBytes+1)
	var out []Entry
	skipped := 0
	for {
		b, tooLong, err := logread.NextLine(r)
		if len(b) > 0 || tooLong {
			if tooLong {
				skipped++
			} else if e, perr := ParseLine(b); perr != nil {
				skipped++
			} else if q.matches(e) {
				out = append(out, e)
				if len(out) > q.Limit {
					out = out[1:]
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, 0, fmt.Errorf("reading an access log: %w", err)
		}
	}
	return out, skipped, budget - lr.N, nil
}
