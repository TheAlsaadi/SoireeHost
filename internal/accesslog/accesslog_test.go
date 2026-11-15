package accesslog

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func line(t testing.TB, fields map[string]any) []byte {
	t.Helper()
	base := map[string]any{"level": "info", "ts": 1794700000.25, "logger": "http.log.access.access", "msg": "handled request", "status": 200, "size": 5, "duration": 0.004}
	for k, v := range fields {
		base[k] = v
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func req(method, host, uri, ua string) map[string]any {
	return map[string]any{"client_ip": "203.0.113.24", "method": method, "host": host, "uri": uri,
		"headers": map[string][]string{"User-Agent": {ua}, "Cookie": {"session=secret"}, "Referer": {"https://a.example.com/?token=abc"}}}
}

// Attacker text is kept as data, bounded, and never gains anything it did
// not have; credentials and query values are not returned (S-18, S-34).
func TestParseLine(t *testing.T) {
	e, err := ParseLine(line(t, map[string]any{"request": req("get", "Blog.Example.com:443", "/<script>alert(1)</script>?q=x", "<img src=x onerror=alert(1)>")}))
	if err != nil {
		t.Fatal(err)
	}
	if e.Method != http.MethodGet || e.Host != "blog.example.com" || e.URI != "/<script>alert(1)</script>?q=REDACTED" {
		t.Fatalf("entry: %+v", e)
	}
	if e.UserAgent != "<img src=x onerror=alert(1)>" || e.Referer != "https://a.example.com/?token=REDACTED" || e.DurationMs != 4 {
		t.Fatalf("entry: %+v", e)
	}
	if want := time.Unix(1794700000, 250000000).UTC(); !e.Time.Equal(want) {
		t.Fatalf("time %v, want %v", e.Time, want)
	}
	if b, _ := json.Marshal(e); strings.Contains(string(b), "secret") || strings.Contains(string(b), "abc") {
		t.Fatalf("a credential leaked: %s", b)
	}
	e, err = ParseLine(line(t, map[string]any{"request": req("G\nET", "evil host", "/\x1b[31m", strings.Repeat("\u202E", 400))}))
	if err != nil {
		t.Fatal(err)
	}
	if e.Method != "OTHER" || e.Host != "" || strings.ContainsRune(e.URI, 0x1b) || len(e.UserAgent) > MaxUserAgent || !utf8.ValidString(e.UserAgent) {
		t.Fatalf("not cleaned: %+v", e)
	}
	for name, bad := range map[string][]byte{
		"not json":      []byte("{"),
		"other logger":  line(t, map[string]any{"logger": "http.handlers.waf"}),
		"no status":     line(t, map[string]any{"status": 0}),
		"no time":       line(t, map[string]any{"ts": -1}),
		"huge line":     []byte(`{"x":"` + strings.Repeat("a", MaxLineBytes) + `"}`),
		"wrong ts type": []byte(`{"ts":"now","logger":"http.log.access.access","status":200}`),
	} {
		if _, err := ParseLine(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReadPagesAndFilters(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := range 10 {
		status := 200
		if i%3 == 0 {
			status = 403
		}
		host := "a.example.com"
		if i%2 == 0 {
			host = "b.example.com"
		}
		lines = append(lines, string(line(t, map[string]any{"ts": 1794700000 + float64(i), "status": status, "request": req("GET", host, "/p", "ua")})))
	}
	lines = append(lines, "garbage")
	if err := os.WriteFile(filepath.Join(dir, LogName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Read(dir, Query{Limit: 4})
	if err != nil || len(p.Entries) != 4 || !p.More || p.Skipped != 1 {
		t.Fatalf("page: %+v %v", p, err)
	}
	if p.Entries[0].Time.Unix() != 1794700009 || p.Entries[3].Time.Unix() != 1794700006 {
		t.Fatalf("not newest first: %v .. %v", p.Entries[0].Time, p.Entries[3].Time)
	}
	p, _ = Read(dir, Query{Class: ClassBlocked})
	if len(p.Entries) != 4 {
		t.Fatalf("blocked class: %d", len(p.Entries))
	}
	p, _ = Read(dir, Query{Hosts: map[string]bool{"a.example.com": true}, After: time.Unix(1794700004, 0)})
	if len(p.Entries) != 3 {
		t.Fatalf("host and after filter: %d", len(p.Entries))
	}
	if p, err := Read(filepath.Join(dir, "missing"), Query{}); err != nil || len(p.Entries) != 0 {
		t.Fatalf("missing folder: %+v %v", p, err)
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add(line(f, map[string]any{"request": req("GET", "a.example.com", "/", "ua")}))
	f.Add([]byte(`{"logger":"http.log.access.x","ts":1e10,"status":599,"request":{"uri":"\u202E"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := ParseLine(b)
		if err != nil {
			return
		}
		if e.Status < 100 || e.Status > 599 || len(e.Method) > maxMethodLen || len(e.UserAgent) > MaxUserAgent ||
			len(e.Referer) > MaxReferer || !utf8.ValidString(e.UserAgent) || strings.ContainsAny(e.URI, " \n\r\x00") {
			t.Fatalf("entry out of shape: %+v", e)
		}
	})
}

// A poll for new entries skips log files last written before its After
// bound, so polling does not reread the whole history (ADR-0009).
func TestReadSkipsOldFilesWhenPolling(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "access-2026-11-01T00-00-00.000.log")
	if err := os.WriteFile(old, append(line(t, map[string]any{"ts": 1794000000.0, "request": req("GET", "a.example.com", "/old", "ua")}), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Unix(1794000000, 0)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, LogName), append(line(t, map[string]any{"ts": 1794700000.0, "request": req("GET", "a.example.com", "/new", "ua")}), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	all, _ := Read(dir, Query{})
	if len(all.Entries) != 2 {
		t.Fatalf("without a bound: %d entries", len(all.Entries))
	}
	recent, _ := Read(dir, Query{After: time.Unix(1794600000, 0)})
	if len(recent.Entries) != 1 || recent.Entries[0].URI != "/new" {
		t.Fatalf("poll read old files: %+v", recent.Entries)
	}
}
