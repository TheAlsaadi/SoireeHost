package supervisor

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

func auditHas(t *testing.T, h *harness, action, key, want string) bool {
	t.Helper()
	var al ipc.AuditListResult
	if err := h.call(ipc.MethodAuditList, ipc.AuditListParams{}, &al); err != nil {
		t.Fatal(err)
	}
	for _, e := range al.Entries {
		if e.Action == action && strings.Contains(e.Detail[key], want) {
			return true
		}
	}
	return false
}

func wantConfirm(t *testing.T, err error, what string) {
	t.Helper()
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired {
		t.Fatalf("%s without confirmation: %v", what, err)
	}
}

// S-14, S-32 (owner decision of 15 Nov 2026): Detect only and Off need
// confirmation and are audited, from site.put, for a new site, and on
// rollback; Off shows a standing warning.
func TestFirewallWeakeningNeedsConfirmation(t *testing.T) {
	h := start(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	defer app.Close()
	site := h.proxySite("app", app.Listener.Addr().String())
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, &res); err != nil {
		t.Fatal(err)
	}
	blockRev := res.Revision
	if fw := res.Config.Sites[0].Firewall; fw.Mode != config.FirewallBlock || fw.ParanoiaLevel != 1 {
		t.Fatalf("new site starts with %+v, want Block at level 1", fw)
	}
	for _, mode := range []string{config.FirewallDetect, config.FirewallOff} {
		s := site
		s.Firewall.Mode = mode
		wantConfirm(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: s}, nil), mode)
		if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: s, Confirm: true}, &res); err != nil {
			t.Fatal(err)
		}
		if !auditHas(t, h, "site.put", "weakening", "firewall") {
			t.Fatalf("%s not audited as weakening", mode)
		}
	}
	if w := strings.Join(res.Warnings, " "); !strings.Contains(w, "turned off") {
		t.Fatalf("no standing warning for Off: %q", w)
	}
	var st ipc.StatusResult
	if err := h.call(ipc.MethodStatus, ipc.None{}, &st); err != nil || !strings.Contains(strings.Join(st.Warnings, " "), "turned off") {
		t.Fatalf("status has no standing warning for Off: %v %v", err, st.Warnings)
	}
	// raising the mode again needs nothing
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, &res); err != nil {
		t.Fatalf("back to Block: %v", err)
	}
	// rolling back to the Off revision is weakening too
	offRev := res.Revision - 1
	wantConfirm(t, h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: offRev}, nil), "rollback to Off")
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: offRev, Confirm: true}, nil); err != nil {
		t.Fatal(err)
	}
	if !auditHas(t, h, "config.rollback", "weakening", "firewall") {
		t.Fatal("rollback to Off not audited as weakening")
	}
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: blockRev}, nil); err != nil {
		t.Fatalf("rollback to Block refused: %v", err)
	}
	// a new site that starts below Block
	n := h.proxySite("raw", app.Listener.Addr().String())
	n.Firewall.Mode = config.FirewallDetect
	wantConfirm(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: n}, nil), "new Detect only site")
}

// Phase 4 check and owner decision of 15 Nov 2026: the exposure check runs
// before a static folder goes live; a served private key needs confirmation,
// a planted .env is listed as never served.
func TestExposureCheckBeforeLive(t *testing.T) {
	// the folder first, so it is removed after the web server let go of it
	root := filepath.Join(testutil.SiteDir(t), "site")
	h := start(t, nil)
	for name, content := range map[string]string{
		"index.html": "HOME", ".env": "DB_PASSWORD=x", "server.key": "k",
		"backup/notes.txt": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIE\n-----END RSA " + "PRIVATE KEY-----\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	site := config.Site{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	var e *ipc.Error
	err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil)
	if !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired || !strings.Contains(e.Message, "backup/notes.txt") {
		t.Fatalf("served key without confirmation: %v", err)
	}
	if strings.Contains(e.Message, "MIIE") {
		t.Fatal("file contents in the message")
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirm: true}, &res); err != nil {
		t.Fatal(err)
	}
	// editing a live site's other settings does not ask again
	renamed := site
	renamed.Name = "Blog, renamed"
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: renamed}, nil); err != nil {
		t.Fatalf("renaming a live site asked again: %v", err)
	}
	if res.Exposure == nil || len(res.Exposure.Served()) != 1 || len(res.Exposure.Findings) != 3 {
		t.Fatalf("exposure report = %+v", res.Exposure)
	}
	if w := strings.Join(res.Warnings, " "); !strings.Contains(w, "never served") {
		t.Fatalf("no warning for the blocked names: %q", w)
	}
	if !auditHas(t, h, "site.put", "weakening", "exposed_files") {
		t.Fatal("confirmed exposure not audited")
	}
	if code, body := get(t, h.listen, "blog.example.com", "/.env"); code != 404 || strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf(".env served: %d %q", code, body)
	}
	// switching it off and on again checks again
	if err := h.call(ipc.MethodSiteSetEnabled, ipc.SiteEnabledParams{ID: "blog", Enabled: false}, nil); err != nil {
		t.Fatal(err)
	}
	wantConfirm(t, h.call(ipc.MethodSiteSetEnabled, ipc.SiteEnabledParams{ID: "blog", Enabled: true}, nil), "re-enabling")
	if err := h.call(ipc.MethodSiteSetEnabled, ipc.SiteEnabledParams{ID: "blog", Enabled: true, Confirm: true}, &res); err != nil {
		t.Fatal(err)
	}
	// a disabled site is saved without a check
	site.ID, site.Hostnames, site.Enabled = "draft", []string{"draft.example.com"}, false
	var draft ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, &draft); err != nil || draft.Exposure != nil {
		t.Fatalf("disabled site: %v %+v", err, draft.Exposure)
	}
}

// A folder that cannot be checked does not go live: a failed check refuses
// the change, and so does a web worker that is not running.
func TestExposureCheckFailsClosed(t *testing.T) {
	root := filepath.Join(testutil.SiteDir(t), "site")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	svc := &fakeServices{webScan: func(ipc.ScanRequest) (sitecheck.ExposureReport, error) {
		return sitecheck.ExposureReport{}, errors.New("disk on fire")
	}}
	h := startWith(t, svc, nil, 20*time.Second)
	site := config.Site{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirm: true}, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid || !strings.Contains(e.Message, "disk on fire") {
		t.Fatalf("failed check: %v", err)
	}
	var cur ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &cur); err != nil || len(cur.Config.Sites) != 0 {
		t.Fatalf("site saved after a failed check: %v %+v", err, cur.Config.Sites)
	}

	down := &Supervisor{}
	down.web = newWorkerMgr(down, ipc.RoleWeb, winsec.WebService, "S-1-5-80-0")
	var w weakenings
	if _, _, perr := down.exposureCheck(site, &w, map[string]string{}); perr == nil || perr.Code != ipc.CodeUnavailable {
		t.Fatalf("worker down: %v", perr)
	}
}

// firewall.events (S-31): typed, validated in the supervisor, and returns
// the events the web worker wrote, newest first.
func TestFirewallEventsMethod(t *testing.T) {
	h := start(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	defer app.Close()
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, h.listen, "app.example.com", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E&token=CANARY77"); code != 403 {
		t.Fatalf("attack: %d", code)
	}
	var res ipc.FirewallEventsResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := h.call(ipc.MethodFirewallEvents, ipc.FirewallEventsParams{SiteID: "app"}, &res); err != nil {
			t.Fatal(err)
		}
		if len(res.Events) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(res.Events) != 1 || res.Events[0].Status != 403 || res.Events[0].URI != "/s?q=REDACTED&token=REDACTED" {
		t.Fatalf("events = %+v", res.Events)
	}
	for _, p := range []ipc.FirewallEventsParams{{SiteID: "../x"}, {Limit: -1}, {Limit: ipc.MaxFirewallPage + 1}} {
		var e *ipc.Error
		if err := h.call(ipc.MethodFirewallEvents, p, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
			t.Errorf("%+v accepted: %v", p, err)
		}
	}
}

// Pre-merge review finding: a load sent while the web worker checks a folder
// is not held up behind the check (and so not timed out and undone).
func TestLoadNotBlockedByScan(t *testing.T) {
	root := filepath.Join(testutil.SiteDir(t), "site")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	scanning := make(chan struct{})
	svc := &fakeServices{webScan: func(ipc.ScanRequest) (sitecheck.ExposureReport, error) {
		close(scanning)
		time.Sleep(3 * time.Second)
		return sitecheck.ExposureReport{Findings: []sitecheck.Finding{}}, nil
	}}
	h := startWith(t, svc, nil, time.Second)
	static := config.Site{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	slow := make(chan error, 1)
	go func() { slow <- h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: static}, nil) }()
	<-scanning
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	defer app.Close()
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatalf("a load during a scan failed: %v", err)
	}
	if err := <-slow; err != nil {
		t.Fatalf("the scanned site: %v", err)
	}
}
