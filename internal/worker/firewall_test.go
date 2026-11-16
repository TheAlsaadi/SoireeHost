package worker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/accesslog"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
)

func marker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "fw" + hex.EncodeToString(b)
}

// waitEvent reads firewall.log the way the supervisor does until an event
// whose URI path holds mark appears.
func waitEvent(t *testing.T, site, mark string) fwevent.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p, err := fwevent.Read(logDir, fwevent.Query{Site: site, Limit: fwevent.MaxPage})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Events {
			if strings.Contains(e.URI, mark) {
				return e
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no firewall event for %s on %s", mark, site)
	return fwevent.Event{}
}

// waitAccess waits for the access-log entry whose path holds mark.
func waitAccess(t *testing.T, mark string) accesslog.Entry {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		p, err := accesslog.Read(logDir, accesslog.Query{Limit: accesslog.MaxPage})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Entries {
			if strings.Contains(e.URI, mark) {
				return e
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no access entry for %s", mark)
	return accesslog.Entry{}
}

// Phase 4 check: sample SQL injection, cross-site scripting and traversal
// requests get a 403 through the whole handler chain and appear in the
// firewall log; normal requests pass (S-14).
func TestFirewallInChain(t *testing.T) {
	h := startHarness(t, nil)
	attacks := map[string]string{
		"sqli":      "/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--",
		"xss":       "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"traversal": "/download?file=../../../../etc/passwd",
		"lfi":       "/view?file=/etc/passwd",
	}
	for name, target := range attacks {
		for _, host := range []string{"blog.example.com", "app.example.com"} {
			mark := marker(t)
			path, query, _ := strings.Cut(target, "?")
			r := h.get(t, host, "/"+mark+path+"?"+query, "CF-Connecting-IP: 203.0.113.9")
			if r.status != 403 {
				t.Errorf("%s on %s: %d %q", name, host, r.status, r.body)
				continue
			}
			checkSecurityHeaders(t, name+" 403", r.header)
			site, _, _ := strings.Cut(host, ".")
			e := waitEvent(t, site, mark)
			if e.Action != fwevent.ActionBlocked || e.Status != 403 || e.ClientIP != "203.0.113.9" || len(e.Rules) == 0 {
				t.Errorf("%s on %s: event %+v", name, host, e)
			}
			if strings.Contains(e.URI, "UNION") || strings.Contains(e.URI, "script") || strings.Contains(e.URI, "passwd") {
				t.Errorf("%s: query value kept in the event: %q", name, e.URI)
			}
			// ADR-0009: Activity names the rule by matching the access-log
			// entry to this event on host, path, client and method
			a := waitAccess(t, mark)
			if a.Host != e.Host || a.URI != e.URI || a.ClientIP != e.ClientIP || a.Method != e.Method || a.Status != 403 {
				t.Errorf("%s on %s: access entry %+v does not match event %+v", name, host, a, e)
			}
		}
	}
	for _, target := range []string{"/", "/index.html", "/sub/page.html?ref=home&utm_source=x"} {
		if r := h.get(t, "blog.example.com", target); r.status != 200 {
			t.Errorf("normal %s: %d", target, r.status)
		}
	}
	if r := h.get(t, "app.example.com", "/api/items?limit=20"); r.status != 200 {
		t.Errorf("normal proxy request: %d %q", r.status, r.body)
	}
}

func TestFirewallModes(t *testing.T) {
	attack := "?q=%3Cscript%3Ealert(1)%3C/script%3E"
	h := startHarness(t, func(c *config.Config) {
		c.Sites[0].Firewall.Mode = config.FirewallDetect
		c.Sites[1].Firewall.Mode = config.FirewallOff
	})
	mark := marker(t)
	if r := h.get(t, "blog.example.com", "/"+mark+"/index.html"+attack); r.status == 403 {
		t.Fatalf("Detect only blocked: %d", r.status)
	}
	if e := waitEvent(t, "blog", mark); e.Action != fwevent.ActionDetected || e.Status != 0 || e.Mode != fwevent.ModeDetect {
		t.Fatalf("Detect only event: %+v", e)
	}
	off := marker(t)
	if r := h.get(t, "app.example.com", "/"+off+attack); r.status != 200 {
		t.Fatalf("Off: %d %q", r.status, r.body)
	}
	time.Sleep(300 * time.Millisecond)
	p, err := fwevent.Read(logDir, fwevent.Query{Site: "app", Limit: fwevent.MaxPage})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Events {
		if strings.Contains(e.URI, off) {
			t.Fatalf("Off wrote an event: %+v", e)
		}
	}
	// the config has no firewall handler for an Off site
	j, err := BuildCaddyJSON(h.cfg, Options{LogDir: logDir})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(j), `"handler":"soireehost_waf"`); n != 2 {
		t.Fatalf("%d firewall handlers for blog (detect), app (off) and files (block); want 2", n)
	}
}

// S-21 (ADR-0008 section 10): the worker's memory with the firewall built
// for every mode and paranoia level, the attack set run through each, and a
// burst of concurrent 15 MB uploads, stays far below the 1 GiB job cap.
func TestFirewallMemory(t *testing.T) {
	// the limit the worker service sets on itself
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(SoftMemoryLimit()))
	h := startHarness(t, func(c *config.Config) {
		for _, mode := range []string{config.FirewallBlock, config.FirewallDetect} {
			for l := 1; l <= config.MaxParanoiaLevel; l++ {
				id := fmt.Sprintf("m-%s-%d", mode, l)
				c.Sites = append(c.Sites, config.Site{ID: id, Name: id, Enabled: true, Hostnames: []string{id + ".example.com"},
					Type: config.TypeProxy, Proxy: &config.Proxy{Target: c.Sites[1].Proxy.Target},
					MaxBodyBytes: 20 << 20, Firewall: config.Firewall{Mode: mode, ParanoiaLevel: l}})
			}
		}
	})
	var peak uint64
	var mu sync.Mutex
	sample := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		mu.Lock()
		peak = max(peak, m.HeapInuse+m.StackInuse)
		mu.Unlock()
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				sample()
			}
		}
	}()
	attacks := []string{"/item?id=1%27%20OR%20%271%27=%271", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/d?f=../../etc/passwd"}
	for _, mode := range []string{config.FirewallBlock, config.FirewallDetect} {
		for l := 1; l <= config.MaxParanoiaLevel; l++ {
			host := fmt.Sprintf("m-%s-%d.example.com", mode, l)
			for _, a := range attacks {
				h.get(t, host, a)
			}
		}
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("f", "clip.mp4")
	_, _ = fw.Write(bytes.Repeat([]byte{1, 2, 3, 4}, (15<<20)/4))
	_ = mw.Close()
	// every upload sends the same bytes; the client keeps no copy of its own
	c := uploadClient(t)
	codes := make([]int, 16)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Go(func() {
			r, err := h.upload(t, c, "m-block-1.example.com", mw.FormDataContentType(), body.Bytes())
			if err != nil {
				t.Errorf("upload %d: %v", i, err)
				return
			}
			codes[i] = r.status
			checkUpload(t, r, body.Len())
		})
	}
	wg.Wait()
	close(stop)
	sample()
	runtime.GC()
	debug.FreeOSMemory()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	passed := 0
	for _, code := range codes {
		if code == http.StatusOK {
			passed++
		}
	}
	t.Logf("S-21 measurement: peak heap+stack %d MiB during the attack set on 8 firewalls and 16 concurrent 15 MB uploads (%d passed, the rest got 503 from the body budget); %d MiB in use after GC; job cap %d MiB",
		peak>>20, passed, after.HeapInuse>>20, Limits.MemoryBytes>>20)
	if peak > Limits.MemoryBytes/4*3 {
		t.Fatalf("peak memory %d MiB is over the soft limit, three quarters of the job cap", peak>>20)
	}
	if passed == 0 {
		t.Fatal("no upload passed")
	}
}

// uploadClient is the HTTP client cloudflared uses towards the worker: Go's
// transport with keep-alive, which reads the response while it is still
// sending the body (RFC 9112 section 9.5).
//
// A refusal the firewall sends before reading a body (503 from the body
// budget or the inspection slots, 413 for too much text) must reach such a
// client. Go's server then shuts its side down and waits before closing.
// h.raw is no client for large bodies: it sends Connection: close and writes
// the whole body before reading. For such a request Go's server closes at
// once with the body unread, Windows resets the connection, and the reset
// can discard the refusal before the client reads it (the TestFirewallMemory
// flake of 15 Nov 2026).
func uploadClient(t *testing.T) *http.Client {
	t.Helper()
	tr := &http.Transport{MaxIdleConnsPerHost: 16}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// upload posts body to /upload on host. It runs in goroutines, so it returns
// errors instead of failing the test.
func (h *harness) upload(t *testing.T, c *http.Client, host, contentType string, body []byte) (result, error) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+h.addr+"/upload", bytes.NewReader(body))
	if err != nil {
		return result{}, err
	}
	req.Host = host
	req.Header.Set("Content-Type", contentType)
	resp, err := c.Do(req)
	if err != nil {
		return result{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return result{}, err
	}
	return result{resp.StatusCode, resp.Header, string(b)}, nil
}

// checkUpload accepts an upload the app received whole, or a 503 from the
// body budget that tells the client when to retry.
func checkUpload(t *testing.T, r result, size int) {
	t.Helper()
	switch r.status {
	case http.StatusOK:
		if !strings.Contains(r.body, fmt.Sprintf(`"body":%d,`, size)) {
			t.Errorf("upload passed, but the app did not receive all %d bytes: %.200q", size, r.body)
		}
	case http.StatusServiceUnavailable:
		if r.header.Get("Retry-After") == "" {
			t.Error("503 without Retry-After")
		}
	default:
		t.Errorf("upload answered %d: %.200q", r.status, r.body)
	}
}

// A refusal the firewall sends before reading the body reaches the client
// even while many such uploads arrive at once. 16 concurrent 8 MB JSON bodies
// each get Block mode's 413 for body text over 128 KB, which is decided from
// Content-Length alone; three rounds.
func TestRefusalBeforeBodyIsAnswered(t *testing.T) {
	h := startHarness(t, nil)
	c := uploadClient(t)
	body := []byte(`{"a":"` + strings.Repeat("x", 8<<20) + `"}`)
	for round := range 3 {
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				r, err := h.upload(t, c, "app.example.com", "application/json", body)
				switch {
				case err != nil:
					t.Errorf("round %d, upload %d: %v", round, i, err)
				case r.status != http.StatusRequestEntityTooLarge:
					t.Errorf("round %d, upload %d: %d %.200q", round, i, r.status, r.body)
				case strings.Contains(r.body, `"body":`):
					t.Errorf("round %d, upload %d: the app received the body", round, i)
				}
			})
		}
		wg.Wait()
	}
}
