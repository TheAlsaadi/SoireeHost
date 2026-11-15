//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

var procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")

// processMemoryCounters is PROCESS_MEMORY_COUNTERS (psapi.h).
type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// peakCommit is a process's peak committed private memory, the figure the
// job object's process memory limit applies to.
func peakCommit(t *testing.T, pid uint32) uint64 {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // query handle
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	r, _, err := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.cb)) //nolint:gosec // G103: Windows API arguments
	if r == 0 {
		t.Fatalf("GetProcessMemoryInfo: %v", err)
	}
	return uint64(c.PeakPagefileUsage)
}

func getPath(t *testing.T, host, path string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+config.DefaultListen+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Phase 4 checks on the installed services (S-14, S-18, S-21, S-31): sample
// attacks get 403 and appear in firewall.events read over the control pipe,
// normal requests pass, and the confined web worker's peak committed memory
// stays under three quarters of its job cap with the firewall loaded and a
// burst of uploads inspected.
func TestFirewallOnInstalledSystem(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = fmt.Fprintf(w, "ok %d", n)
	}))
	defer app.Close()
	site := config.Site{ID: "fw", Name: "Firewall", Enabled: true, Hostnames: []string{"fw.e2e.example"},
		Type: config.TypeProxy, Proxy: &config.Proxy{Target: app.Listener.Addr().String()}, MaxBodyBytes: 20 << 20}
	if err := call(t, c, ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	attacks := []string{
		"/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--",
		"/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
		"/download?file=../../../../etc/passwd",
		"/view?file=/etc/passwd&token=E2E-CANARY-QUERY",
	}
	for _, a := range attacks {
		if code := getPath(t, "fw.e2e.example", a); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", a, code)
		}
	}
	for _, p := range []string{"/", "/api/items?limit=20", "/search?q=how+to+self-host"} {
		if code := getPath(t, "fw.e2e.example", p); code != http.StatusOK {
			t.Errorf("normal %s: %d", p, code)
		}
	}
	var res ipc.FirewallEventsResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := call(t, c, ipc.MethodFirewallEvents, ipc.FirewallEventsParams{SiteID: "fw"}, &res); err != nil {
			t.Fatal(err)
		}
		if len(res.Events) >= len(attacks) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(res.Events) < len(attacks) || res.Skipped != 0 {
		t.Fatalf("firewall.events: %d events, %d skipped lines", len(res.Events), res.Skipped)
	}
	for _, e := range res.Events {
		if err := e.Validate(); err != nil || e.Status != http.StatusForbidden || e.Action != fwevent.ActionBlocked {
			t.Errorf("event %+v: %v", e, err)
		}
		if strings.Contains(e.URI, "CANARY") || strings.Contains(e.URI, "UNION") {
			t.Errorf("query value in an event: %q", e.URI)
		}
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("f", "clip.mp4")
	_, _ = fw.Write(bytes.Repeat([]byte{1, 2, 3, 4}, (15<<20)/4))
	_ = mw.Close()
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for range 16 {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+config.DefaultListen+"/upload", bytes.NewReader(body.Bytes()))
			req.Host = "fw.e2e.example"
			req.Header.Set("Content-Type", mw.FormDataContentType())
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			codes <- resp.StatusCode
		})
	}
	wg.Wait()
	close(codes)
	passed := 0
	for code := range codes {
		if code == http.StatusOK {
			passed++
		} else if code != http.StatusServiceUnavailable {
			t.Errorf("upload answered %d", code)
		}
	}
	peak := peakCommit(t, state(t, winsec.WebService).ProcessId)
	limit := worker.Limits.MemoryBytes
	t.Logf("S-21 measurement (installed web worker): peak committed memory %d MiB of the %d MiB job cap; %d of 16 concurrent 15 MB uploads passed, the rest got 503 from the body budget",
		peak>>20, limit>>20, passed)
	if peak > limit/4*3 {
		t.Fatalf("peak committed memory %d MiB is over three quarters of the %d MiB job cap", peak>>20, limit>>20)
	}
	if passed == 0 {
		t.Fatal("no upload passed")
	}
}
