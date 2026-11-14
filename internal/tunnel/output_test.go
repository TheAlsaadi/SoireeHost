package tunnel

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lines in the form cloudflared 2026.11.0 writes with --output json
// (cliutil.LogTable, connection/observer.go, orchestration/orchestrator.go).
const (
	lineRequest = `{"level":"info","time":"2026-11-14T10:00:00Z","message":"Requesting new quick Tunnel on trycloudflare.com..."}`
	lineBorder  = `{"level":"info","time":"2026-11-14T10:00:01Z","message":"+--------------------------------------------------------------------------------------------+"}`
	lineCreated = `{"level":"info","time":"2026-11-14T10:00:01Z","message":"|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |"}`
	lineURL     = `{"level":"info","time":"2026-11-14T10:00:01Z","message":"|  https://seasonal-deck-organisms-sf.trycloudflare.com                                      |"}`
)

func registered(i int) string {
	return fmt.Sprintf(`{"level":"info","event":0,"connIndex":%d,"connection":"6ff42ae2-765d-4adf-8112-31c55c1551ef","ip":"198.41.200.13","location":"ams01","protocol":"http2","time":"2026-11-14T10:00:02Z","message":"Registered tunnel connection"}`, i)
}

func unregistered(i int) string {
	return fmt.Sprintf(`{"level":"info","connIndex":%d,"time":"2026-11-14T10:05:00Z","message":"Unregistered tunnel connection"}`, i)
}

func newConfig(t *testing.T, cfg any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(map[string]any{"level": "info", "version": 3, "config": string(b), "message": "Updated to new configuration"})
	if err != nil {
		t.Fatal(err)
	}
	return string(line)
}

func TestQuickShareHostnameFromOutput(t *testing.T) {
	s := newOutputState(true, 8787)
	for _, l := range []string{lineRequest, lineBorder, lineCreated, lineURL, lineBorder} {
		s.feed([]byte(l))
	}
	if s.hostname != "seasonal-deck-organisms-sf.trycloudflare.com" {
		t.Fatalf("hostname = %q", s.hostname)
	}
	// a later line, for example a request path in an error, cannot change it
	s.feed([]byte(`{"level":"info","message":"|  https://attacker.trycloudflare.com  |"}`))
	if s.hostname != "seasonal-deck-organisms-sf.trycloudflare.com" {
		t.Fatalf("hostname changed to %q", s.hostname)
	}
}

func TestQuickShareHostnameOnlyBeforeFirstConnection(t *testing.T) {
	s := newOutputState(true, 8787)
	s.feed([]byte(registered(0)))
	s.feed([]byte(lineURL))
	if s.hostname != "" {
		t.Fatalf("hostname accepted after a connection: %q", s.hostname)
	}
	for _, bad := range []string{
		`{"message":"|  https://evil.example.com  |"}`,
		`{"message":"|  https://a.b.trycloudflare.com  |"}`,
		`{"message":"see https://x.trycloudflare.com"}`,
		`|  https://plain-text.trycloudflare.com  |`,
	} {
		s := newOutputState(true, 8787)
		s.feed([]byte(bad))
		if s.hostname != "" {
			t.Errorf("%s gave hostname %q", bad, s.hostname)
		}
	}
	// a token tunnel never takes a quick share hostname
	tok := newOutputState(false, 8787)
	tok.feed([]byte(lineURL))
	if tok.hostname != "" {
		t.Fatal("token tunnel took a hostname")
	}
}

func TestConnectionCount(t *testing.T) {
	s := newOutputState(false, 8787)
	for i := range 4 {
		if !s.feed([]byte(registered(i))) {
			t.Fatalf("registration %d not a change", i)
		}
	}
	s.feed([]byte(registered(2))) // repeated
	if s.connections() != 4 || !s.everConnected {
		t.Fatalf("connections = %d", s.connections())
	}
	s.feed([]byte(unregistered(1)))
	s.feed([]byte(unregistered(9))) // never registered
	if s.connections() != 3 {
		t.Fatalf("connections = %d", s.connections())
	}
	if s.feed([]byte(`not json`)) || s.feed([]byte(`{"message":"Registered tunnel connection"}`)) {
		t.Fatal("a malformed line changed the state")
	}
}

// TestIngressCheck: the dashboard may only send traffic to SoiréeHost's own
// listener (ADR-0007 section 3).
func TestIngressCheck(t *testing.T) {
	type rule = map[string]any
	cfg := func(rules ...rule) map[string]any {
		return map[string]any{"ingress": rules, "warp-routing": map[string]any{"enabled": false}}
	}
	ok := []map[string]any{
		cfg(rule{"hostname": "a.example.com", "service": "http://127.0.0.1:8787"}, rule{"service": "http_status:404"}),
		cfg(rule{"hostname": "a.example.com", "service": "http://localhost:8787/"}, rule{"service": "http_status:404"}),
		cfg(rule{"service": "http://[::1]:8787"}),
	}
	bad := []map[string]any{
		cfg(rule{"hostname": "a.example.com", "service": "http://192.168.1.10:80"}, rule{"service": "http_status:404"}),
		cfg(rule{"service": "http://127.0.0.1:3000"}),
		cfg(rule{"service": "https://127.0.0.1:8787"}),
		cfg(rule{"service": "ssh://localhost:22"}),
		cfg(rule{"service": "hello_world"}),
		cfg(rule{"service": "http_status:abc"}),
		{"ingress": []rule{{"service": "http://127.0.0.1:8787"}}, "warp-routing": map[string]any{"enabled": true}},
	}
	for _, c := range ok {
		s := newOutputState(false, 8787)
		s.feed([]byte(newConfig(t, c)))
		if s.ingressOutside {
			t.Errorf("%v flagged", c)
		}
	}
	for _, c := range bad {
		s := newOutputState(false, 8787)
		if !s.feed([]byte(newConfig(t, c))) || !s.ingressOutside {
			t.Errorf("%v not flagged", c)
		}
	}
	s := newOutputState(false, 8787)
	s.feed([]byte(`{"message":"Updated to new configuration","config":"not json"}`))
	if !s.ingressOutside {
		t.Error("an unreadable configuration was not flagged")
	}
}

func testToken(t testing.TB) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"a": "0123456789abcdef0123456789abcdef",
		"t": "6ff42ae2-765d-4adf-8112-31c55c1551ef",
		"s": base64.StdEncoding.EncodeToString([]byte("CANARY-TUNNEL-SECRET-0123456789ab")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestScrubber (R-21): the token and its parts never survive a log line.
func TestScrubber(t *testing.T) {
	tok := testToken(t)
	raw := []byte("CANARY-TUNNEL-SECRET-0123456789ab")
	sc := newScrubber(tok)
	for _, leak := range []string{
		tok,
		base64.StdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		"0123456789abcdef0123456789abcdef",
	} {
		line := []byte(`{"level":"error","message":"failed with token ` + leak + ` here"}`)
		out := string(sc.scrub(line))
		if strings.Contains(out, leak) || !strings.Contains(out, redacted) {
			t.Errorf("not scrubbed: %s", out)
		}
	}
	if got := newScrubber("").scrub([]byte("x")); string(got) != "x" {
		t.Fatal("empty scrubber changed a line")
	}
}

func TestReadLines(t *testing.T) {
	long := strings.Repeat("x", MaxLineBytes+100)
	in := "a\r\nb\n" + long + "\nc"
	var got []string
	if err := readLines(strings.NewReader(in), func(b []byte) { got = append(got, string(b)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0] != "a" || got[1] != "b" || len(got[2]) > MaxLineBytes || got[3] != "c" {
		t.Fatalf("got %d lines: %q %q len=%d %q", len(got), got[0], got[1], len(got[2]), got[len(got)-1])
	}
}

// TestPinMatchesLock: the pin compiled into the binary is the lock file's
// (S-71: one source for the hash).
func TestPinMatchesLock(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "build", "cloudflared.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && !strings.HasPrefix(k, "#") {
			vals[k] = v
		}
	}
	if vals["version"] != CloudflaredVersion || vals["sha256"] != CloudflaredSHA256 || vals["asset"] != "cloudflared-windows-amd64.exe" {
		t.Fatalf("lock %v does not match pin %s %s", vals, CloudflaredVersion, CloudflaredSHA256)
	}
}

func TestEmbedded(t *testing.T) {
	b, err := Embedded()
	if len(embedded) == 0 {
		if !errors.Is(err, ErrNotEmbedded) {
			t.Fatalf("err = %v", err)
		}
		return
	}
	if err != nil || len(b) == 0 {
		t.Fatalf("embedded cloudflared refused: %v", err)
	}
}

// FuzzOutput: no line panics the parser or the scrubber, a hostname is only
// ever a valid quick share hostname, and the scrubber leaves no token behind.
func FuzzOutput(f *testing.F) {
	for _, l := range []string{lineRequest, lineCreated, lineURL, registered(0), unregistered(0),
		`{"message":"Updated to new configuration","config":"{\"ingress\":[{\"service\":\"http://127.0.0.1:8787\"}]}"}`} {
		f.Add([]byte(l))
	}
	tok := testToken(f)
	sc := newScrubber(tok)
	f.Fuzz(func(t *testing.T, line []byte) {
		for _, quick := range []bool{true, false} {
			s := newOutputState(quick, 8787)
			s.feed(line)
			s.feed(line)
			if s.hostname != "" && (!quick || !strings.HasSuffix(s.hostname, ".trycloudflare.com")) {
				t.Fatalf("hostname %q", s.hostname)
			}
			if s.connections() > 16 {
				t.Fatal("too many connections")
			}
		}
		withTok := append(append(append([]byte{}, line...), tok...), line...)
		if bytes.Contains(sc.scrub(withTok), []byte(tok)) {
			t.Fatal("token survived the scrubber")
		}
	})
}
