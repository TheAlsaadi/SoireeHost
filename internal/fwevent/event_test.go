package fwevent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() Event {
	return Event{
		Time: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC), Site: "blog", Mode: ModeBlock, Action: ActionBlocked,
		Status: 403, ParanoiaLevel: 1, Method: "GET", Host: "blog.example.com",
		URI: "/search?q=<script>&token=SECRET1", ClientIP: "203.0.113.7",
		Rules: []Rule{{ID: 941100, Severity: "critical", Msg: "XSS Attack Detected via libinjection", Where: []string{"ARGS"}}},
	}
}

func logLine(t *testing.T, e Event) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"level": "warn", "ts": "2026-11-15T10:00:00Z", "logger": "http.handlers.soireehost_waf", "msg": LogMessage, "event": e})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCleanMasksAndValidates(t *testing.T) {
	e := sample().Clean([]string{"<script>"})
	if err := e.Validate(); err != nil {
		t.Fatalf("cleaned event does not validate: %v", err)
	}
	if strings.Contains(e.URI, "SECRET1") || strings.Contains(e.URI, "<script>") {
		t.Fatalf("query values kept: %q", e.URI)
	}
	if e.URI != "/search?q=REDACTED&token=REDACTED" {
		t.Fatalf("URI = %q", e.URI)
	}
}

func TestCleanDropsBadFields(t *testing.T) {
	e := sample()
	e.Host = "evil.example\r\nX: y"
	e.ClientIP = "not-an-ip"
	e.Method = "GET /x"
	e.URI = "/a\x00b c\xffd?x=1"
	e.Rules = append(e.Rules,
		Rule{ID: 0, Msg: "bad id"},
		Rule{ID: 942100, Severity: "bogus", Msg: "Matched SECRETVALUE here", Where: []string{"ARGS:password", "REQUEST_HEADERS", "TX"}},
		Rule{ID: 920100, Msg: "line\nbreak"})
	c := e.Clean([]string{"secretvalue"})
	if err := c.Validate(); err != nil {
		t.Fatalf("cleaned event does not validate: %v", err)
	}
	if c.Host != "" || c.ClientIP != "" || c.Method != "OTHER" {
		t.Fatalf("bad fields kept: %+v", c)
	}
	if c.URI != "/a%00b%20c%FFd?x=REDACTED" {
		t.Fatalf("URI = %q", c.URI)
	}
	if len(c.Rules) != 3 {
		t.Fatalf("rules = %+v", c.Rules)
	}
	if r := c.Rules[1]; r.Msg != PlaceholderMs || r.Severity != "" || strings.Join(r.Where, ",") != "REQUEST_HEADERS,TX" {
		t.Fatalf("rule kept a matched value, a bad severity or a key: %+v", r)
	}
	if c.Rules[2].Msg != PlaceholderMs {
		t.Fatalf("message with a line break kept: %q", c.Rules[2].Msg)
	}
}

func TestCleanCapsRulesAndURI(t *testing.T) {
	e := sample()
	for i := range 20 {
		e.Rules = append(e.Rules, Rule{ID: 942000 + i, Msg: "m"})
	}
	e.URI = "/" + strings.Repeat("a", 5000) + "?k=" + strings.Repeat("v", 100)
	c := e.Clean(nil)
	if len(c.Rules) != MaxRules || len(c.URI) > MaxURILen || !strings.HasSuffix(c.URI, "?REDACTED") {
		t.Fatalf("not capped: %d rules, URI %d bytes ending %q", len(c.Rules), len(c.URI), c.URI[len(c.URI)-12:])
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseLineStrict(t *testing.T) {
	good := logLine(t, sample().Clean(nil))
	if _, err := ParseLine(good); err != nil {
		t.Fatalf("good line refused: %v", err)
	}
	bad := map[string][]byte{
		"unknown field": []byte(strings.Replace(string(good), `"site":`, `"extra":1,"site":`, 1)),
		"trailing data": append(append([]byte{}, good...), []byte(` {}`)...),
		"other message": []byte(strings.Replace(string(good), LogMessage, "something else", 1)),
		"no event":      []byte(`{"level":"warn","ts":1,"logger":"x","msg":"firewall event"}`),
		"unmasked uri":  []byte(strings.Replace(string(good), `q=REDACTED`, `q=SECRET`, 1)),
		"bad status":    []byte(strings.Replace(string(good), `"status":403`, `"status":200`, 1)),
		"bad site":      []byte(strings.Replace(string(good), `"site":"blog"`, `"site":"../x"`, 1)),
		"too long":      []byte(`{"msg":"` + strings.Repeat("a", MaxLineBytes) + `"}`),
		"not json":      []byte("hello"),
	}
	for name, b := range bad {
		if _, err := ParseLine(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadNewestFirstAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mod time.Time, evs ...Event) {
		var b strings.Builder
		for _, e := range evs {
			b.Write(logLine(t, e.Clean(nil)))
			b.WriteString("\n")
		}
		b.WriteString("garbage line\n")
		b.WriteString(strings.Repeat("x", MaxLineBytes+10) + "\n")
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	at := func(min int, site string) Event {
		e := sample()
		e.Time, e.Site = base.Add(time.Duration(min)*time.Minute), site
		return e
	}
	write("firewall-2026-11-14T00-00-00.000.log", base.Add(-time.Hour), at(1, "blog"), at(2, "shop"))
	write(LogName, base.Add(time.Hour), at(3, "blog"), at(4, "blog"))
	write("other.log", base.Add(2*time.Hour), at(9, "blog"))

	p, err := Read(dir, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var mins []int
	for _, e := range p.Events {
		mins = append(mins, int(e.Time.Sub(base)/time.Minute))
	}
	if fmt.Sprint(mins) != "[4 3 2 1]" || p.Skipped != 4 || p.More {
		t.Fatalf("got %v skipped %d more %v", mins, p.Skipped, p.More)
	}
	p, _ = Read(dir, Query{Site: "blog", Limit: 2})
	if len(p.Events) != 2 || p.Events[0].Time != at(4, "").Time || !p.More {
		t.Fatalf("site page: %+v more %v", p.Events, p.More)
	}
	p, _ = Read(dir, Query{Before: at(3, "").Time, Limit: 10})
	if len(p.Events) != 2 || p.Events[0].Site != "shop" {
		t.Fatalf("before page: %+v", p.Events)
	}
	if p, err := Read(filepath.Join(dir, "missing"), Query{}); err != nil || len(p.Events) != 0 {
		t.Fatalf("missing folder: %v %+v", err, p)
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add(logLine(&testing.T{}, sample().Clean(nil)))
	f.Add([]byte(`{"level":"warn","ts":1,"logger":"x","msg":"firewall event","event":{}}`))
	f.Add([]byte(`{"msg":"firewall event","event":{"uri":"/?a=1#b","rules":[{"id":1,"msg":"x","where":["ARGS"]}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := ParseLine(b)
		if err != nil {
			return
		}
		// anything accepted is valid and already safe to show
		if err := e.Validate(); err != nil {
			t.Fatalf("accepted an invalid event: %v", err)
		}
		if CleanURI(e.URI) != e.URI {
			t.Fatalf("accepted an unmasked URI: %q", e.URI)
		}
	})
}

// FuzzClean: whatever the request held, the cleaned event validates and
// keeps no query value (S-18).
func FuzzClean(f *testing.F) {
	f.Add("/a?token=CANARYxyz", "GET", "blog.example.com", "1.2.3.4", "msg", "ARGS")
	f.Add("/p?a=1#&token=CANARYxyz", "POST", "", "::ffff:1.2.3.4", "Matched CANARYxyz", "REQUEST_HEADERS")
	f.Add("/x?CANARYxyz", "\x00", "a\r\nb", "fe80::1%eth0", "\n", "lower")
	f.Fuzz(func(t *testing.T, uri, method, host, ip, msg, where string) {
		e := Event{Time: time.Unix(1, 0), Site: "blog", Mode: ModeDetect, Action: ActionDetected, ParanoiaLevel: 2,
			Method: method, Host: host, URI: uri, ClientIP: ip, Rules: []Rule{{ID: 5, Msg: msg, Where: []string{where}}}}
		c := e.Clean([]string{"CANARYxyz"})
		if err := c.Validate(); err != nil {
			t.Fatalf("cleaned event does not validate: %v (%+v)", err, c)
		}
		// S-18 keeps parameter names and masks every value and bare item
		if _, q, ok := strings.Cut(c.URI, "?"); ok {
			for g := range strings.SplitSeq(q, "&") {
				for p := range strings.SplitSeq(g, ";") {
					name, value, hasValue := strings.Cut(p, "=")
					if (hasValue && value != "REDACTED") || (!hasValue && name != "" && name != "REDACTED") {
						t.Fatalf("query value kept: %q", c.URI)
					}
				}
			}
		}
		if strings.Contains(c.Rules[0].Msg, "CANARYxyz") {
			t.Fatalf("matched value kept in the message: %q", c.Rules[0].Msg)
		}
	})
}
