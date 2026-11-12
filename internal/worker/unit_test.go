package worker

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

func TestLimiterBurstThenRate(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(300, time.Minute, 100, func() time.Time { return now })
	for i := range 300 {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d refused", i+1)
		}
	}
	ok, retry := l.allow("a")
	if ok {
		t.Fatal("request 301 allowed")
	}
	if retry <= 0 || retry > 200*time.Millisecond {
		t.Fatalf("retry = %v, want about one interval (200ms)", retry)
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("other client refused")
	}
	now = now.Add(200 * time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("not allowed after one interval")
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("two allowed after one interval")
	}
	now = now.Add(time.Minute)
	for i := range 300 {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("after a minute, request %d refused", i+1)
		}
	}
}

func TestLimiterBoundedAndFailsClosed(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(10, time.Minute, 3, func() time.Time { return now })
	for _, k := range []string{"a", "b", "c"} {
		if ok, _ := l.allow(k); !ok {
			t.Fatal("refused")
		}
	}
	if ok, _ := l.allow("d"); ok {
		t.Fatal("new client allowed while table full")
	}
	if l.size() != 3 {
		t.Fatalf("size %d", l.size())
	}
	now = now.Add(time.Minute)
	if ok, _ := l.allow("d"); !ok {
		t.Fatal("new client refused after entries expired")
	}
	if l.size() != 1 {
		t.Fatalf("expired entries not swept: size %d", l.size())
	}
}

func TestClientKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"":                     "invalid",
		"not-an-ip":            "invalid",
	}
	for in, want := range cases {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripForwarded(t *testing.T) {
	h := http.Header{}
	for _, k := range forwardedHeaders {
		h.Set(k, "6.6.6.6")
	}
	h.Set("Cf-Connecting-Ip", "203.0.113.7")
	h.Set("X-Forwarded-Proto", "https")
	h["X_forwarded_for"] = []string{"6.6.6.6"}
	h["X_real_ip"] = []string{"6.6.6.6"}
	h["X_forwarded_proto"] = []string{"http"}
	h["X_custom"] = []string{"kept"}
	StripForwarded(h)
	for _, k := range []string{"X_forwarded_for", "X_real_ip", "X_forwarded_proto"} {
		if _, ok := h[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	if v := h["X_custom"]; len(v) != 1 || v[0] != "kept" {
		t.Error("unrelated underscore header dropped")
	}
	for _, k := range forwardedHeaders {
		if h.Get(k) != "" {
			t.Errorf("%s kept", k)
		}
	}
	if h.Get("Cf-Connecting-Ip") != "203.0.113.7" || h.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("wrong headers dropped: %v", h)
	}
	for _, v := range [][]string{{"javascript"}, {"https", "http"}, {"HTTPS "}} {
		h := http.Header{"X-Forwarded-Proto": v}
		StripForwarded(h)
		if _, ok := h["X-Forwarded-Proto"]; ok {
			t.Errorf("X-Forwarded-Proto %q kept", v)
		}
	}
}

func TestRedactURI(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: URIs with fake secret parameters the filter must mask
		"/":                                     "/",
		"/a?page=2":                             "/a?page=2",
		"/a?token=abc&page=2":                   "/a?token=REDACTED&page=2",
		"/a?access_token=abc":                   "/a?access_token=REDACTED",
		"/a?API_KEY=abc":                        "/a?API_KEY=REDACTED",
		"/a?Password=x&user=bob":                "/a?Password=REDACTED&user=bob",
		"/a?client_secret=x":                    "/a?client_secret=REDACTED",
		"/a?pass%77ord=x":                       "/a?pass%77ord=REDACTED",
		"/a?x=1;token=abc":                      "/a?x=1;token=REDACTED",
		"/a?%zz=1":                              "/a?REDACTED",
		"/a?sessionid=1#frag":                   "/a?sessionid=REDACTED#frag",
		"https://x.example/p?sig=1&signature=2": "https://x.example/p?sig=1&signature=REDACTED",
		"/a?token":                              "/a?token",
		"/a?keyword=foo":                        "/a?keyword=REDACTED",
	}
	for in, want := range cases {
		if got := RedactURI(in); got != want {
			t.Errorf("RedactURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterHeaders(t *testing.T) {
	h := http.Header{
		"Authorization":           {"Bearer s"},
		"Cookie":                  {"a=b"},
		"Set-Cookie":              {"a=b"},
		"Cf-Access-Jwt-Assertion": {"jwt"},
		"X-Api-Key":               {"k"},
		"Proxy-Authorization":     {"p"},
		"User-Agent":              {"ua"},
		"Referer":                 {"https://x.example/?token=s&q=1"},
		"Content-Type":            {"text/html"},
	}
	got := FilterHeaders(h)
	if len(got) != 3 || got.Get("User-Agent") != "ua" || got.Get("Content-Type") != "text/html" ||
		got.Get("Referer") != "https://x.example/?token=REDACTED&q=1" {
		t.Fatalf("got %v", got)
	}
}

func TestFiltersDropUnexpectedTypes(t *testing.T) {
	if f := (HeaderFilter{}).Filter(zap.String("headers", "Authorization: x")); f.Type != zapcore.SkipType {
		t.Fatal("header filter kept a string field")
	}
	if f := (QueryFilter{}).Filter(zap.Int("uri", 1)); f.Type != zapcore.SkipType {
		t.Fatal("query filter kept a non-string field")
	}
	f := (HeaderFilter{}).Filter(zap.Object("headers", caddyhttp.LoggableHTTPHeader{Header: http.Header{"Cookie": {"x"}}, ShouldLogCredentials: true}))
	lh, ok := f.Interface.(caddyhttp.LoggableHTTPHeader)
	if !ok || len(lh.Header) != 0 || lh.ShouldLogCredentials {
		t.Fatalf("filtered = %#v", f.Interface)
	}
}

func TestCheckEndpoints(t *testing.T) {
	ok := []Endpoint{
		{"tcp", netip.MustParseAddrPort("127.0.0.1:8787")},
		{"tcp", netip.MustParseAddrPort("[::1]:8787")},
	}
	if err := checkEndpoints(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0:8787", "[::]:8787", "192.168.1.2:80", "127.0.0.2:80", "[::ffff:127.0.0.1]:80"} {
		eps := append(append([]Endpoint{}, ok...), Endpoint{"tcp", netip.MustParseAddrPort(bad)})
		if err := checkEndpoints(eps); err == nil {
			t.Errorf("%s passed", bad)
		}
	}
	if err := checkEndpoints([]Endpoint{{"udp", netip.MustParseAddrPort("0.0.0.0:53")}}); err == nil {
		t.Error("UDP wildcard passed")
	}
}

func TestParseTableRejectsGarbage(t *testing.T) {
	k := tableKinds[0]
	if _, err := parseTable([]byte{1}, k, 1); err == nil {
		t.Error("short table accepted")
	}
	if _, err := parseTable([]byte{0xff, 0xff, 0, 0, 1, 2, 3}, k, 1); err == nil {
		t.Error("count larger than buffer accepted")
	}
	row := make([]byte, 4+24)
	row[0] = 1
	copy(row[4+4:], []byte{127, 0, 0, 1})
	row[4+8], row[4+9] = 0x22, 0x53 // port 8787
	row[4+20] = 42
	eps, err := parseTable(row, k, 42)
	if err != nil || len(eps) != 1 || eps[0].Addr != netip.MustParseAddrPort("127.0.0.1:8787") {
		t.Fatalf("eps=%v err=%v", eps, err)
	}
}

// S-04 and S-01: the generated config has no admin endpoint, never autosaves,
// listens only on the configured loopback address, uses HTTP/1 only (no UDP)
// and serves only enabled sites.
func TestBuildCaddyJSON(t *testing.T) {
	c := config.Default()
	c.Sites = []config.Site{
		{ID: "on", Name: "On", Enabled: true, Hostnames: []string{"on.example.com"}, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3000"}},
		{ID: "off", Name: "Off", Enabled: false, Hostnames: []string{"off.example.com"}, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3001"}},
		{ID: "nohost", Name: "No host", Enabled: true, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3002"}},
	}
	c.Normalize()
	j, err := BuildCaddyJSON(c, Options{LogDir: `C:\logs`})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(j, &root); err != nil {
		t.Fatal(err)
	}
	admin := root["admin"].(map[string]any)
	if admin["disabled"] != true || admin["config"].(map[string]any)["persist"] != false {
		t.Fatalf("admin = %v", admin)
	}
	srv := root["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)[serverName].(map[string]any)
	if l := srv["listen"].([]any); len(l) != 1 || l[0] != "127.0.0.1:8787" {
		t.Fatalf("listen = %v", l)
	}
	if p := srv["protocols"].([]any); len(p) != 1 || p[0] != "h1" {
		t.Fatalf("protocols = %v", p)
	}
	if _, ok := srv["metrics"]; ok {
		t.Fatal("metrics enabled")
	}
	s := string(j)
	if !strings.Contains(s, "on.example.com") || strings.Contains(s, "off.example.com") || strings.Contains(s, "3002") {
		t.Fatalf("wrong sites served: %s", s)
	}
	// S-18: both logs are filtered and rotate with a size cap
	// (encoding/json escapes ">" as backslash-u003e; undo that first)
	norm := strings.ReplaceAll(s, string([]byte{'\\', 'u', '0', '0', '3', 'e'}), ">")
	for _, want := range []string{`"roll_size_mb":10`, `"roll_keep":5`, `"request>headers":{"filter":"soireehost_headers"}`, `"request>uri":{"filter":"soireehost_query"}`, `"resp_headers":{"filter":"soireehost_headers"}`} {
		if strings.Count(norm, want) != 2 {
			t.Errorf("config has %q %d times, want once per log", want, strings.Count(norm, want))
		}
	}
	for _, banned := range []string{"0.0.0.0", "pprof", "\"metrics\"", ":2019"} {
		if strings.Contains(s, banned) {
			t.Errorf("config contains %q", banned)
		}
	}

	bad := c
	bad.Listen = "0.0.0.0:8787"
	if _, err := BuildCaddyJSON(bad, Options{LogDir: `C:\logs`}); err == nil {
		t.Fatal("built a config with a public listener")
	}
	if _, err := BuildCaddyJSON(c, Options{LogDir: `logs`}); err == nil {
		t.Fatal("accepted relative log folder")
	}
}
