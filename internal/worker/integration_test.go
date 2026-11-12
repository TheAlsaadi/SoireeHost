package worker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

// Every planted secret contains this marker; no response body or log line may
// ever contain it.
const secretMarker = "PLANTED-SECRET"

type harness struct {
	addr     string
	logDir   string
	root     string
	outside  string
	upstream *httptest.Server
	cfg      config.Config
}

// logDir is shared by every test in the package. Caddy keeps a log file open
// for the life of the process once it has opened it, so a per-test temporary
// folder could not be removed; this one is cleared at the start of each run.
var logDir string

func TestMain(m *testing.M) {
	logDir = filepath.Join(os.TempDir(), "soireehost-worker-test-logs")
	_ = os.RemoveAll(logDir)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func listen(t *testing.T, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(t.Context(), "tcp", addr)
}

func dial(t *testing.T, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(t.Context(), "tcp", addr)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := listen(t, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// echoUpstream answers with the request headers it received as JSON, reads
// and counts the body, and sets headers the worker must handle.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		w.Header().Set("Server", "upstream/1.0")
		w.Header().Set("Set-Cookie", "sid="+secretMarker+"-SETCOOKIE")
		if r.URL.Path == "/own-csp" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}
		if err != nil {
			http.Error(w, "body read failed", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": r.Header, "body": n, "host": r.Host})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startHarness runs a worker with three sites: a static site, a proxy site and
// a static site with directory listing on. mutate may change the config first.
func startHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	h := &harness{logDir: logDir}
	base := testutil.SiteDir(t)
	h.root = filepath.Join(base, "site")
	h.outside = filepath.Join(base, "outside")
	writeFile(t, filepath.Join(h.outside, "secret.txt"), secretMarker+"-OUTSIDE")

	r := h.root
	writeFile(t, filepath.Join(r, "index.html"), "INDEX-OK")
	writeFile(t, filepath.Join(r, "sub", "index.html"), "SUB-INDEX")
	writeFile(t, filepath.Join(r, "sub", "page.html"), "SUB-PAGE")
	writeFile(t, filepath.Join(r, "nolist", "file.txt"), "NOLIST")
	for _, name := range []string{
		".env", ".ENV2", ".git/config", ".well-known/secret", "key.pem", "Key2.PEM", "server.key", "cert.pfx",
		"cert.p12", "backup.bak", "dump.sql", "web.config", "desktop.ini", "Thumbs.db", "sub/.htpasswd",
		".secretlongname", "listing/.env", "listing/id.key",
	} {
		writeFile(t, filepath.Join(r, filepath.FromSlash(name)), secretMarker+"-"+name)
	}
	writeFile(t, filepath.Join(r, "listing", "visible.txt"), "VISIBLE")
	writeFile(t, filepath.Join(r, ".well-known", "security.txt"), "CONTACT")
	writeFile(t, filepath.Join(r, ".well-known", ".env"), secretMarker+"-WK-ENV")
	writeFile(t, filepath.Join(r, ".well-known", "id.key"), secretMarker+"-WK-KEY")
	testutil.Junction(t, filepath.Join(r, "escape"), h.outside)
	if err := os.Symlink(filepath.Join(h.outside, "secret.txt"), filepath.Join(r, "link.txt")); err != nil {
		t.Logf("symbolic link not created (needs Developer Mode or admin): %v", err)
	}
	if err := os.Symlink(`..\outside\secret.txt`, filepath.Join(r, "rellink.txt")); err != nil {
		t.Logf("relative symbolic link not created: %v", err)
	}

	h.upstream = echoUpstream(t)
	port := freePort(t)
	h.addr = fmt.Sprintf("127.0.0.1:%d", port)

	c := config.Default()
	c.Listen = h.addr
	c.Sites = []config.Site{
		{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com", "www.blog.example.com"},
			Type: config.TypeStatic, Static: &config.Static{Root: r}},
		{ID: "app", Name: "App", Enabled: true, Hostnames: []string{"app.example.com"},
			Type: config.TypeProxy, Proxy: &config.Proxy{Target: h.upstream.Listener.Addr().String()}},
		{ID: "files", Name: "Files", Enabled: true, Hostnames: []string{"files.example.com"},
			Type: config.TypeStatic, Static: &config.Static{Root: filepath.Join(r, "listing"), DirectoryListing: true}},
		{ID: "off", Name: "Off", Enabled: false, Hostnames: []string{"off.example.com"},
			Type: config.TypeStatic, Static: &config.Static{Root: r}},
	}
	if mutate != nil {
		mutate(&c)
	}
	c.Normalize()
	h.cfg = c
	if err := Load(c, Options{LogDir: h.logDir}); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() {
		if err := Stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	})
	return h
}

type result struct {
	status int
	header http.Header
	body   string
}

// raw sends a request exactly as written, so nothing in a Go HTTP client can
// clean or re-encode the path, and reads one response.
func (h *harness) raw(t *testing.T, request string) result {
	t.Helper()
	c, err := dial(t, h.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading response to %q: %v", request, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, resp.Header, string(b)}
}

func (h *harness) get(t *testing.T, host, target string, headers ...string) result {
	t.Helper()
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", target, host)
	for _, x := range headers {
		sb.WriteString(x + "\r\n")
	}
	sb.WriteString("\r\n")
	return h.raw(t, sb.String())
}

func TestStaticServes(t *testing.T) {
	h := startHarness(t, nil)
	cases := map[string]string{"/": "INDEX-OK", "/index.html": "INDEX-OK", "/sub/": "SUB-INDEX", "/sub/page.html": "SUB-PAGE"}
	for target, want := range cases {
		r := h.get(t, "blog.example.com", target)
		if r.status != 200 || r.body != want {
			t.Errorf("GET %s = %d %q, want 200 %q", target, r.status, r.body, want)
		}
	}
	if r := h.get(t, "WWW.Blog.Example.com:8787", "/"); r.status != 200 {
		t.Errorf("host match is not case-insensitive or port-tolerant: %d", r.status)
	}
	if r := h.get(t, "blog.example.com", "/sub"); r.status != http.StatusPermanentRedirect && r.status != http.StatusMovedPermanently && r.status != http.StatusFound {
		t.Errorf("directory without slash: %d", r.status)
	}
}

// Plan section 10, path traversal suite (S-11, S-12, S-13): each request must
// get 400 or 404 and never any file content.
func TestPathTraversalSuite(t *testing.T) {
	h := startHarness(t, nil)
	targets := []string{
		"/../win.ini", "/..%2fwin.ini", "/..%2Fwin.ini", "/..%5cwin.ini", "/..%5Cwin.ini", `/..\win.ini`,
		"/%2e%2e/win.ini", "/%2e%2e%2fwin.ini", "/%252e%252e/win.ini", "/%252e%252e%252fwin.ini",
		"/..%c0%af../win.ini", "/%c0%ae%c0%ae/win.ini",
		"/../outside/secret.txt", "/..%2foutside%2fsecret.txt", "/sub/../../outside/secret.txt",
		"/SECRET~1.TXT", "/SECRET~1", "/ESCAPE~1/secret.txt", "/KEY~1.PEM",
		"/index.html::$DATA", "/key.pem::$DATA", "/.env::$DATA", "/index.html:stream",
		"/index.html.", "/key.pem.", "/index.html%20", "/key.pem%20", "/.env%20", "/key.pem%00", "/key.pem%00.html",
		"/CON", "/con", "/nul.txt", "/COM1", "/LPT1.txt", "/AUX", "/CONIN$",
		"/.git/config", "/.GIT/config", "/.env", "/.ENV", "/.Env", "/.ENV2", "/.well-known/secret", "/sub/.htpasswd",
		"/.secretlongname", "/%2eenv", "/%2Eenv",
		"/key.pem", "/key.PEM", "/Key2.PEM", "/server.key", "/cert.pfx", "/cert.P12", "/backup.bak", "/dump.sql",
		"/web.config", "/WEB.CONFIG", "/desktop.ini", "/Desktop.INI", "/Thumbs.db", "/thumbs.DB",
		"/escape/secret.txt", "/escape/", "/link.txt", "/rellink.txt",
		"/C:/Windows/win.ini", "/C:%5cWindows%5cwin.ini", "//evil.example/", "/%2f%2fevil.example/",
		"/nolist/", "/nolist",
	}
	for _, target := range targets {
		r := h.get(t, "blog.example.com", target)
		if r.status != 400 && r.status != 404 {
			t.Errorf("GET %s = %d, want 400 or 404 (body %q)", target, r.status, r.body)
		}
		if strings.Contains(r.body, secretMarker) || strings.Contains(r.body, "INDEX-OK") || strings.Contains(r.body, "NOLIST") {
			t.Errorf("GET %s leaked content: %q", target, r.body)
		}
	}
	// the same suite against the proxy site must never reach the app with a
	// traversal or a never-serve name
	for _, target := range []string{"/../x", "/..%2fx", "/..%5cx", "/.env", "/.git/config", "/key.pem", "/a%00b"} {
		r := h.get(t, "app.example.com", target)
		if r.status != 400 && r.status != 404 {
			t.Errorf("proxy GET %s = %d, want 400 or 404", target, r.status)
		}
	}
}

// S-12: no listing unless turned on, and a listing leaves out refused names.
func TestDirectoryListing(t *testing.T) {
	h := startHarness(t, nil)
	if r := h.get(t, "blog.example.com", "/nolist/"); r.status != 404 {
		t.Errorf("listing without opt-in: %d %q", r.status, r.body)
	}
	r := h.get(t, "files.example.com", "/", "Accept: text/html")
	if r.status != 200 || !strings.Contains(r.body, "visible.txt") {
		t.Fatalf("listing: %d %q", r.status, r.body)
	}
	if strings.Contains(r.body, ".env") || strings.Contains(r.body, "id.key") {
		t.Errorf("listing shows refused names: %q", r.body)
	}
	if r := h.get(t, "files.example.com", "/id.key"); r.status != 404 {
		t.Errorf("key served from listing site: %d", r.status)
	}
}

// S-06: a Host that is not a configured site hostname gets a 404.
func TestUnknownHost(t *testing.T) {
	h := startHarness(t, nil)
	for _, host := range []string{"evil.example", "127.0.0.1", h.addr, "localhost", "blog.example.com.evil.example", "off.example.com", "example.com"} {
		r := h.get(t, host, "/")
		if r.status != 404 || strings.Contains(r.body, "INDEX-OK") {
			t.Errorf("Host %q: %d %q", host, r.status, r.body)
		}
		checkSecurityHeaders(t, "Host "+host, r.header)
	}
	// Go's HTTP server itself refuses an HTTP/1.1 request with an empty Host
	if r := h.get(t, "", "/"); r.status != 400 || strings.Contains(r.body, "INDEX-OK") {
		t.Errorf("empty Host: %d %q", r.status, r.body)
	}
	r := h.raw(t, "GET / HTTP/1.0\r\n\r\n")
	if r.status != 404 && r.status != 400 {
		t.Errorf("HTTP/1.0 without Host: %d", r.status)
	}
	r = h.raw(t, "GET http://evil.example/ HTTP/1.1\r\nHost: blog.example.com\r\nConnection: close\r\n\r\n")
	if r.status != 404 && r.status != 400 {
		t.Errorf("absolute-form target for another host: %d %q", r.status, r.body)
	}
}

func checkSecurityHeaders(t *testing.T, what string, hdr http.Header) {
	t.Helper()
	for k, v := range config.DefaultHeaders() {
		if got := hdr.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", what, k, got, v)
		}
	}
	if s := hdr.Values("Server"); len(s) != 0 {
		t.Errorf("%s: Server header %q", what, s)
	}
}

// S-16: default headers on every kind of response, no Server header, the
// app's own stricter header kept, per-site overrides applied.
func TestSecurityHeaders(t *testing.T) {
	h := startHarness(t, func(c *config.Config) {
		c.Sites[2].ResponseHeaders = map[string]string{"Referrer-Policy": "no-referrer", "Content-Security-Policy": ""}
	})
	checkSecurityHeaders(t, "static 200", h.get(t, "blog.example.com", "/").header)
	checkSecurityHeaders(t, "static 404", h.get(t, "blog.example.com", "/missing.html").header)
	checkSecurityHeaders(t, "guard 400", h.get(t, "blog.example.com", "/CON").header)
	checkSecurityHeaders(t, "guard 404", h.get(t, "blog.example.com", "/.env").header)
	checkSecurityHeaders(t, "proxy 200", h.get(t, "app.example.com", "/").header)

	own := h.get(t, "app.example.com", "/own-csp").header
	if got := own.Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("app's own CSP replaced: %q", got)
	}
	ov := h.get(t, "files.example.com", "/visible.txt").header
	if ov.Get("Referrer-Policy") != "no-referrer" || ov.Get("Content-Security-Policy") != "" || ov.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("override not applied: %v", ov)
	}
}

// S-05: forged forwarding headers never reach the app; the app sees the
// address from CF-Connecting-IP.
func TestForwardedHeaders(t *testing.T) {
	h := startHarness(t, nil)
	r := h.get(t, "app.example.com", "/",
		"X-Forwarded-For: 6.6.6.6", "X-Real-IP: 6.6.6.6", "Forwarded: for=6.6.6.6", "True-Client-IP: 6.6.6.6",
		"X-Client-IP: 6.6.6.6", "X-Forwarded-Host: evil.example", "X-Forwarded-Proto: https",
		"CF-Connecting-IP: 203.0.113.7")
	if r.status != 200 {
		t.Fatalf("status %d %q", r.status, r.body)
	}
	var got struct {
		Headers http.Header `json:"headers"`
		Host    string      `json:"host"`
	}
	if err := json.Unmarshal([]byte(r.body), &got); err != nil {
		t.Fatal(err)
	}
	if xff := got.Headers.Values("X-Forwarded-For"); len(xff) != 1 || xff[0] != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q", xff)
	}
	for _, k := range []string{"X-Real-Ip", "Forwarded", "True-Client-Ip", "X-Client-Ip", "Via"} {
		if v := got.Headers.Get(k); v != "" {
			t.Errorf("%s reached the app: %q", k, v)
		}
	}
	if v := got.Headers.Get("X-Forwarded-Host"); v != "app.example.com" {
		t.Errorf("X-Forwarded-Host = %q", v)
	}
	if v := got.Headers.Get("X-Forwarded-Proto"); v != "https" {
		t.Errorf("X-Forwarded-Proto = %q", v)
	}
	if got.Host != "app.example.com" {
		t.Errorf("Host = %q", got.Host)
	}

	r = h.get(t, "app.example.com", "/", "X-Forwarded-For: 6.6.6.6", "X-Forwarded-Proto: gopher")
	_ = json.Unmarshal([]byte(r.body), &got)
	if xff := got.Headers.Get("X-Forwarded-For"); xff != "127.0.0.1" {
		t.Errorf("without CF-Connecting-IP, X-Forwarded-For = %q", xff)
	}
	if v := got.Headers.Get("X-Forwarded-Proto"); v != "http" {
		t.Errorf("forged X-Forwarded-Proto passed: %q", v)
	}
}

// S-15: request body limit (default 10 MB).
func TestBodyLimit(t *testing.T) {
	h := startHarness(t, nil)
	limit := config.DefaultMaxBodyBytes
	post := func(n int64, chunked bool) result {
		var sb strings.Builder
		sb.WriteString("POST /upload HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n")
		if chunked {
			sb.WriteString("Transfer-Encoding: chunked\r\n\r\n")
			fmt.Fprintf(&sb, "%x\r\n%s\r\n0\r\n\r\n", n, strings.Repeat("a", int(n)))
		} else {
			fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n%s", n, strings.Repeat("a", int(n)))
		}
		return h.raw(t, sb.String())
	}
	if r := post(limit, false); r.status != 200 {
		t.Errorf("body at the limit: %d", r.status)
	}
	if r := post(limit+1, false); r.status != http.StatusRequestEntityTooLarge {
		t.Errorf("body over the limit: %d", r.status)
	}
	if r := post(limit+1, true); r.status != http.StatusRequestEntityTooLarge && r.status != http.StatusBadGateway {
		t.Errorf("chunked body over the limit: %d", r.status)
	} else if strings.Contains(r.body, `"body":`) {
		t.Errorf("app received the oversized body: %q", r.body)
	}
}

// S-15: per-client rate limit, default 300 a minute, keyed on CF-Connecting-IP.
func TestRateLimit(t *testing.T) {
	h := startHarness(t, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	do := func(ip string) (int, http.Header) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+h.addr+"/", nil)
		req.Host = "blog.example.com"
		req.Header.Set("CF-Connecting-IP", ip)
		// a forged X-Forwarded-For that changes every time must not reset the count
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", time.Now().Nanosecond()%250))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	// The limiter refills continuously (one request per 200 ms at 300 a
	// minute), so the first refusal comes after 300 requests plus one for
	// each 200 ms the burst took to send.
	start := time.Now()
	status, header := 0, http.Header{}
	allowed := 0
	for range 2 * config.DefaultRateLimitPerMinute {
		status, header = do("203.0.113.7")
		if status != http.StatusOK {
			break
		}
		allowed++
	}
	refill := int(time.Since(start)/(time.Minute/time.Duration(config.DefaultRateLimitPerMinute))) + 1
	if status != http.StatusTooManyRequests {
		t.Fatalf("after %d requests: %d", allowed, status)
	}
	if allowed < config.DefaultRateLimitPerMinute || allowed > config.DefaultRateLimitPerMinute+refill {
		t.Fatalf("%d requests allowed before 429, want %d to %d", allowed, config.DefaultRateLimitPerMinute, config.DefaultRateLimitPerMinute+refill)
	}
	if header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	checkSecurityHeaders(t, "429", header)
	if status, _ := do("203.0.113.8"); status != http.StatusOK {
		t.Errorf("other client: %d", status)
	}
}

// S-15: header size cap and read-header timeout.
func TestHeaderLimitAndTimeout(t *testing.T) {
	h := startHarness(t, func(c *config.Config) { c.Server.ReadHeaderTimeoutSeconds = 1 })
	big := "X-Big: " + strings.Repeat("a", config.DefaultMaxHeaderBytes+8192) // Go allows 4 KB of slack
	if r := h.get(t, "blog.example.com", "/", big); r.status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized headers: %d", r.status)
	}

	c, err := dial(t, h.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: blog.example.com\r\n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadAll(c) // returns when the server closes the connection
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("slow headers held the connection for %v", d)
	}
}

// S-18: credentials and secret query values never reach the logs.
func TestLogRedaction(t *testing.T) {
	h := startHarness(t, nil)
	s := secretMarker
	for _, host := range []string{"app.example.com", "blog.example.com", "unknown.example"} {
		h.get(t, host, "/path?token="+s+"-TOKEN&password="+s+"-PW&api_key="+s+"-KEY&client_secret="+s+"-CS&page=2",
			"Authorization: Bearer "+s+"-AUTH",
			"Proxy-Authorization: Basic "+s+"-PAUTH",
			"Cookie: session="+s+"-COOKIE",
			"X-Api-Key: "+s+"-APIKEY",
			"Cf-Access-Jwt-Assertion: "+s+"-JWT",
			"Referer: https://ref.example/?secret="+s+"-REF&q=1",
			"User-Agent: test-agent/1.0",
			"CF-Connecting-IP: 203.0.113.9")
	}
	access, err := os.ReadFile(filepath.Join(h.logDir, AccessLogName))
	if err != nil {
		t.Fatal(err)
	}
	all := string(access)
	if worker, err := os.ReadFile(filepath.Join(h.logDir, WorkerLogName)); err == nil {
		all += string(worker)
	}
	if strings.Contains(all, secretMarker) {
		for _, line := range strings.Split(all, "\n") {
			if strings.Contains(line, secretMarker) {
				t.Errorf("secret in log: %s", line)
			}
		}
	}
	for _, want := range []string{"page=2", "token=REDACTED", "test-agent/1.0", "203.0.113.9", `"status":200`, `"status":404`} {
		if !strings.Contains(string(access), want) {
			t.Errorf("access log lacks %q:\n%s", want, access)
		}
	}
}

// S-04 and S-01: after loading, the process listens only on the configured
// loopback address, has no admin endpoint and wrote no config autosave.
func TestNoAdminAndOnlyLoopback(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)
	t.Setenv("XDG_CONFIG_HOME", dataDir)
	before, beforeErr := os.Stat(caddy.ConfigAutosavePath)

	h := startHarness(t, nil)
	r := h.get(t, "blog.example.com", "/")
	if r.status != 200 {
		t.Fatal(r.status)
	}
	eps, err := OwnEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	// Earlier tests' listeners may still be closing, so this checks that the
	// worker's socket is there, that every socket is TCP (no HTTP/3 UDP), that
	// nothing serves Caddy's admin port, and (below) that all are loopback.
	found := false
	for _, ep := range eps {
		if ep.Addr.String() == h.addr {
			found = true
		}
		if ep.Proto != "tcp" || ep.Addr.Port() == 2019 {
			t.Errorf("unexpected endpoint %s %s", ep.Proto, ep.Addr)
		}
	}
	if !found {
		t.Errorf("worker listener %s not in %v", h.addr, eps)
	}
	if err := CheckOwnListeners(); err != nil {
		t.Fatal(err)
	}
	if c, err := dial(t, "127.0.0.1:2019", time.Second); err == nil {
		_ = c.Close()
		t.Error("something answers on Caddy's default admin port 2019")
	}
	after, afterErr := os.Stat(caddy.ConfigAutosavePath)
	if (beforeErr != nil) != (afterErr != nil) || (afterErr == nil && !after.ModTime().Equal(before.ModTime())) {
		t.Errorf("config autosaved to %s", caddy.ConfigAutosavePath)
	}
	if entries, _ := os.ReadDir(dataDir); len(entries) != 0 {
		t.Errorf("worker wrote to its data folder: %v", entries)
	}
}

// S-01: the self-check stops a worker whose config listens beyond loopback.
// Binding a non-loopback address makes Windows Firewall prompt on a desktop,
// so this runs only in CI (GitHub sets CI=true).
func TestSelfCheckStopsPublicListener(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("binds a non-loopback address, which makes Windows Firewall prompt on a desktop; runs in CI")
	}
	port := freePort(t)
	j := fmt.Sprintf(`{"admin":{"disabled":true,"config":{"persist":false}},"apps":{"http":{"servers":{"x":{"listen":["0.0.0.0:%d"],"protocols":["h1"],"automatic_https":{"disable":true}}}}}}`, port)
	err := LoadJSON([]byte(j))
	if err == nil {
		_ = Stop()
		t.Fatal("worker kept running with a 0.0.0.0 listener")
	}
	if !strings.Contains(err.Error(), "S-01") {
		t.Errorf("error does not name the self-check: %v", err)
	}
	// Caddy closes its listeners while it shuts the server down, so allow a
	// moment before calling the port still taken
	var l net.Listener
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err = listen(t, fmt.Sprintf("0.0.0.0:%d", port))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener was not released after the failed self-check: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := CheckOwnListeners(); err == nil {
		t.Error("self-check missed a 0.0.0.0 listener opened outside Caddy")
	}
	_ = l.Close()
}

func TestOwnEndpointsSeesLoopbackListener(t *testing.T) {
	l, err := listen(t, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	l6, err6 := listen(t, "[::1]:0")
	if err6 == nil {
		defer func() { _ = l6.Close() }()
	}
	eps, err := OwnEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{l.Addr().String(): false}
	if err6 == nil {
		want[l6.Addr().String()] = false
	}
	for _, ep := range eps {
		if _, ok := want[ep.Addr.String()]; ok && ep.Proto == "tcp" {
			want[ep.Addr.String()] = true
		}
	}
	for a, seen := range want {
		if !seen {
			t.Errorf("listener %s not found in %v", a, eps)
		}
	}
}

// Owner decision 12 Nov 2026: /.well-known/ is served only on sites that opt
// in, and only that folder; everything inside it keeps the other rules.
func TestWellKnownOptIn(t *testing.T) {
	h := startHarness(t, func(c *config.Config) {
		c.Sites = append(c.Sites,
			config.Site{ID: "wk", Name: "WK", Enabled: true, Hostnames: []string{"wk.example.com"}, AllowWellKnown: true,
				Type: config.TypeStatic, Static: &config.Static{Root: c.Sites[0].Static.Root}},
			config.Site{ID: "wkapp", Name: "WK app", Enabled: true, Hostnames: []string{"wkapp.example.com"}, AllowWellKnown: true,
				Type: config.TypeProxy, Proxy: &config.Proxy{Target: c.Sites[1].Proxy.Target}})
	})
	if r := h.get(t, "wk.example.com", "/.well-known/security.txt"); r.status != 200 || r.body != "CONTACT" {
		t.Errorf("opted-in static site: %d %q", r.status, r.body)
	}
	if r := h.get(t, "blog.example.com", "/.well-known/security.txt"); r.status != 404 {
		t.Errorf("default static site: %d %q", r.status, r.body)
	}
	if r := h.get(t, "wkapp.example.com", "/.well-known/openid-configuration"); r.status != 200 {
		t.Errorf("opted-in proxy site: %d %q", r.status, r.body)
	}
	if r := h.get(t, "app.example.com", "/.well-known/openid-configuration"); r.status != 404 {
		t.Errorf("default proxy site: %d", r.status)
	}
	for _, target := range []string{
		"/.well-known/.env", "/.well-known/id.key", "/.well-known/../.env", "/.well-known/..%2f.env",
		"/.WELL-KNOWN/security.txt", "/.well-known./security.txt", "/.well-known::$DATA", "/sub/.well-known/x",
		"/.env", "/.git/config", "/key.pem",
	} {
		for _, host := range []string{"wk.example.com", "wkapp.example.com"} {
			r := h.get(t, host, target)
			if r.status != 400 && r.status != 404 {
				t.Errorf("%s%s = %d, want 400 or 404", host, target, r.status)
			}
			if strings.Contains(r.body, secretMarker) {
				t.Errorf("%s%s leaked %q", host, target, r.body)
			}
		}
	}
}
