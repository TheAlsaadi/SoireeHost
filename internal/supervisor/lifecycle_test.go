package supervisor

// Regression tests for the worker-lifecycle findings of the Phases 0-2
// skills review (docs/reviews/2026-11-12-skills-review.md), restored from
// their fp-check proof tests: R-22 (S-41: a change the web worker cannot
// apply is undone in every failure mode) and R-24 (ADR-0006 lifecycle).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

func okApp(t *testing.T) *httptest.Server {
	t.Helper()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	t.Cleanup(app.Close)
	return app
}

// siteIDs returns the IDs of the current revision's sites.
func siteIDs(h *harness) []string {
	h.t.Helper()
	var cur ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &cur); err != nil {
		h.t.Fatal(err)
	}
	var ids []string
	for _, s := range cur.Config.Sites {
		ids = append(ids, s.ID)
	}
	return ids
}

// loadsWith makes the web worker run fn on loads whose Caddy config holds
// marker, and load everything else normally.
func loadsWith(marker string, fn func(die func()) error) func(func(), ipc.WorkerMsg) error {
	return func(die func(), m ipc.WorkerMsg) error {
		if bytes.Contains(m.Caddy, []byte(marker)) {
			return fn(die)
		}
		return worker.LoadJSON(m.Caddy)
	}
}

// R-22 (1): the worker dies while loading a new revision. The change is
// undone, and the restarted worker serves the restored settings.
func TestWorkerCrashOnChangeIsUndone(t *testing.T) {
	svc := &fakeServices{webLoad: loadsWith("crash.example.com", func(die func()) error {
		die()
		return errors.New("process died")
	})}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("crash", app.Listener.Addr().String())}, nil)
	if err == nil {
		t.Fatal("a change that killed the web worker was reported as applied")
	}
	if ids := siteIDs(h); slices.Contains(ids, "crash") {
		t.Fatalf("the change stayed current: %v", ids)
	}
	h.waitWorkers(StateRunning)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if code, _ := get(t, h.listen, "app.example.com", "/"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the restarted worker does not serve the restored settings")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// R-22 (2): the worker does not answer in time. The change is undone.
func TestWorkerTimeoutOnChangeIsUndone(t *testing.T) {
	svc := &fakeServices{webLoad: loadsWith("slow.example.com", func(func()) error {
		time.Sleep(5 * time.Second)
		return nil
	})}
	h := startWith(t, svc, nil, 2*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("slow", app.Listener.Addr().String())}, nil); err == nil {
		t.Fatal("a change the worker never confirmed was reported as applied")
	}
	if ids := siteIDs(h); slices.Contains(ids, "slow") {
		t.Fatalf("the change stayed current: %v", ids)
	}
}

// R-22 (3): the last good revision cannot be read when a change is refused.
// The settings in force before the change are restored instead.
func TestRefusedChangeRestoresWhenLastGoodUnreadable(t *testing.T) {
	var h *harness
	svc := &fakeServices{}
	svc.webLoad = loadsWith("refuse.example.com", func(func()) error {
		good := h.sup.store.LastGood()
		p := filepath.Join(h.paths.Config(), "history", strconv.FormatUint(good, 10)+".json")
		_ = os.WriteFile(p, []byte("{damaged"), 0o600) // disk damage at the worst moment
		return errors.New("refused by the test worker")
	})
	h = startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("refuse", app.Listener.Addr().String())}, nil); err == nil {
		t.Fatal("refused change reported as applied")
	}
	ids := siteIDs(h)
	if slices.Contains(ids, "refuse") || !slices.Contains(ids, "app") {
		t.Fatalf("after the refusal the sites are %v; want the settings before the change", ids)
	}
}

// R-22: an explicit refusal with a readable last good revision is restored.
func TestRefusedChangeIsUndone(t *testing.T) {
	svc := &fakeServices{webLoad: loadsWith("refuse.example.com", func(func()) error {
		return errors.New("refused by the test worker")
	})}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("refuse", app.Listener.Addr().String())}, nil)
	if ids := siteIDs(h); slices.Contains(ids, "refuse") || err == nil {
		t.Fatalf("explicit refusal not restored: %v %v", ids, err)
	}
}

// R-24 (3): a worker that says hello and then dies is restarted with the
// growing delay (1, 2, 4 ... s), not every second.
func TestRestartBackoffSurvivesHello(t *testing.T) {
	var dieNow atomic.Bool
	svc := &fakeServices{}
	svc.webLoad = func(die func(), m ipc.WorkerMsg) error {
		if dieNow.Load() {
			die()
			return errors.New("died after hello")
		}
		return worker.LoadJSON(m.Caddy)
	}
	startWith(t, svc, nil, 20*time.Second)
	dieNow.Store(true)
	defer dieNow.Store(false)
	before := svc.startCount(winsec.WebService)
	svc.kill(winsec.WebService)
	time.Sleep(10 * time.Second)
	if n := svc.startCount(winsec.WebService) - before; n > 5 {
		t.Fatalf("%d restarts in 10 s; the delay was reset by every hello", n)
	}
}

// R-24 (2): the supervisor tells a worker to stop before closing its pipe.
func TestStopIsSentToWorkers(t *testing.T) {
	var gotStop atomic.Bool
	svc := &fakeServices{rawWeb: func(ctx context.Context, pipe, sid string) {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := ipc.Dial(dctx, pipe, sid)
		cancel()
		if err != nil {
			return
		}
		wc := ipc.NewWorkerConn(conn, ipc.RoleWeb)
		defer func() { _ = wc.Close() }()
		if wc.Send(ipc.WorkerMsg{Type: ipc.MsgHello, Role: ipc.RoleWeb}) != nil {
			return
		}
		for {
			m, err := wc.Recv()
			if err != nil {
				return
			}
			switch m.Type {
			case ipc.MsgStop:
				gotStop.Store(true)
				return
			case ipc.MsgLoad:
				_ = wc.Send(ipc.WorkerMsg{Type: ipc.MsgLoaded, Revision: m.Revision})
			}
		}
	}}
	h := startWith(t, svc, nil, 20*time.Second)
	h.stop()
	time.Sleep(500 * time.Millisecond)
	if !gotStop.Load() {
		t.Fatal("the supervisor stopped without sending stop (ADR-0006 lifecycle)")
	}
}

// R-24 (4): an idle control connection does not hold up the supervisor's
// exit (it used to wait up to ipc.IdleTimeout, 5 minutes).
func TestIdleControlConnectionDoesNotStallExit(t *testing.T) {
	h := start(t)
	me, _ := winsec.CurrentCaller()
	dctx, dcancel := context.WithTimeout(t.Context(), 5*time.Second)
	idle, err := ipc.DialControl(dctx, h.sup.opts.Pipes.Control, me.SID)
	dcancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()
	var st ipc.StatusResult
	if err := idle.Call(t.Context(), ipc.MethodStatus, ipc.None{}, &st); err != nil {
		t.Fatal(err)
	}
	_ = h.client.Close()
	h.client = nil
	cancel := h.cancel
	h.cancel = nil
	cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Errorf("supervisor stopped with: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("one idle control connection kept the supervisor from exiting")
	}
}

// R-24 (1): a worker restart is recorded (in the audit log; the supervisor
// cannot write the worker's own log folder).
func TestWorkerRestartIsRecorded(t *testing.T) {
	svc := &fakeServices{}
	h := startWith(t, svc, nil, 20*time.Second)
	svc.kill(winsec.WebService)
	deadline := time.Now().Add(15 * time.Second)
	for svc.startCount(winsec.WebService) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	h.waitWorkers(StateRunning)
	var page ipc.AuditListResult
	if err := h.call(ipc.MethodAuditList, ipc.AuditListParams{Limit: ipc.MaxAuditPage}, &page); err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Entries {
		if e.Action == "worker.restart" && e.Detail["role"] == ipc.RoleWeb {
			return
		}
	}
	t.Fatal("the web worker restarted but no worker.restart entry was recorded")
}

// saveBehindWorker stores a revision with one more proxy site without the
// web worker loading it, as a change saved while the worker was down.
func saveBehindWorker(h *harness, id, target string) uint64 {
	h.t.Helper()
	h.sup.changeMu.Lock()
	defer h.sup.changeMu.Unlock()
	cur, err := h.sup.store.Current()
	if err != nil {
		h.t.Fatal(err)
	}
	cfg := cur.Config
	cfg.Sites = append(slices.Clone(cfg.Sites), h.proxySite(id, target))
	rec, err := h.sup.store.Save(cfg, winsec.SIDSystem, "saved while the worker was down")
	if err != nil {
		h.t.Fatal(err)
	}
	return rec.Revision
}

// waitRestored waits for the current revision to lose site id, then checks
// the audit entry names the cause.
func waitRestored(t *testing.T, h *harness, id, cause string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for slices.Contains(siteIDs(h), id) {
		if time.Now().After(deadline) {
			t.Fatalf("settings the web worker cannot load were not restored at connect: %v", siteIDs(h))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !auditHas(t, h, "config.restored", "cause", cause) {
		t.Fatalf("no config.restored entry with cause %s", cause)
	}
}

// S-41 (owner's decision of 27 Nov 2026): saved settings that kill the web
// worker at two connects in a row are replaced by the last good revision,
// and the restarted worker serves it.
func TestCrashAtConnectRestoresLastGood(t *testing.T) {
	var crashes atomic.Int32
	svc := &fakeServices{webLoad: loadsWith("boom.example.com", func(die func()) error {
		crashes.Add(1)
		die()
		return errors.New("process died")
	})}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	saveBehindWorker(h, "boom", app.Listener.Addr().String())
	svc.kill(winsec.WebService)
	waitRestored(t, h, "boom", "stopped")
	if n := crashes.Load(); n != 2 {
		t.Errorf("the worker loaded the bad settings %d times; one death gets one more start", n)
	}
	h.waitWorkers(StateRunning)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if code, _ := get(t, h.listen, "app.example.com", "/"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the restarted worker does not serve the restored settings")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// S-41: saved settings the web worker hangs on past the load timeout at
// connect are replaced by the last good revision at once.
func TestHangAtConnectRestoresLastGood(t *testing.T) {
	svc := &fakeServices{webLoad: loadsWith("hang.example.com", func(func()) error {
		time.Sleep(5 * time.Second)
		return nil
	})}
	h := startWith(t, svc, nil, 2*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	saveBehindWorker(h, "hang", app.Listener.Addr().String())
	svc.kill(winsec.WebService)
	waitRestored(t, h, "hang", "timed_out")
}

// S-41: one death at connect is not blamed on the settings: a worker that
// dies once and then loads them keeps them.
func TestOneCrashAtConnectKeepsSettings(t *testing.T) {
	var crashes atomic.Int32
	svc := &fakeServices{webLoad: loadsWith("flaky.example.com", func(die func()) error {
		if crashes.Add(1) == 1 {
			die()
			return errors.New("process died")
		}
		return nil
	})}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	rev := saveBehindWorker(h, "flaky", app.Listener.Addr().String())
	svc.kill(winsec.WebService)
	deadline := time.Now().Add(20 * time.Second)
	for h.sup.store.LastGood() != rev {
		if time.Now().After(deadline) {
			t.Fatalf("the settings were not loaded on the second start (%d loads)", crashes.Load())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !slices.Contains(siteIDs(h), "flaky") {
		t.Fatal("settings that loaded on the second start were replaced")
	}
}

// Security review SR-1: an automatic restore never undoes a tightening saved
// since the last good revision. Here the saved settings switch a site off;
// the last good revision has it on, so the saved settings stay as they are
// and the failed restore is reported.
func TestRestoreNeverSwitchesASiteBackOn(t *testing.T) {
	svc := &fakeServices{webLoad: loadsWith("boom.example.com", func(die func()) error {
		die()
		return errors.New("process died")
	})}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	for _, id := range []string{"app", "leak"} {
		if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite(id, app.Listener.Addr().String())}, nil); err != nil {
			t.Fatal(err)
		}
	}
	h.sup.changeMu.Lock()
	cur, err := h.sup.store.Current()
	if err == nil {
		cfg := cur.Config
		cfg.Sites = slices.Clone(cfg.Sites)
		for i := range cfg.Sites {
			if cfg.Sites[i].ID == "leak" {
				cfg.Sites[i].Enabled = false
			}
		}
		cfg.Sites = append(cfg.Sites, h.proxySite("boom", app.Listener.Addr().String()))
		_, err = h.sup.store.Save(cfg, winsec.SIDSystem, "saved while the worker was down")
	}
	h.sup.changeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	svc.kill(winsec.WebService)
	deadline := time.Now().Add(30 * time.Second)
	for !auditHas(t, h, "config.restore_failed", "failed_revision", "") {
		if time.Now().After(deadline) {
			t.Fatal("the refused restore was not reported")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var now ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &now); err != nil {
		t.Fatal(err)
	}
	for _, s := range now.Config.Sites {
		if s.ID == "leak" && s.Enabled {
			t.Fatal("the automatic restore switched a site back on")
		}
	}
	if !slices.Contains(siteIDs(h), "boom") {
		t.Fatal("the saved settings were replaced")
	}
}

// SR-1: the weakening test behind it, case by case.
func TestRestoreWeakens(t *testing.T) {
	base := config.Default()
	base.Sites = []config.Site{{ID: "a", Name: "A", Enabled: true, Hostnames: []string{"a.example.com"}, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3000"}}}
	with := func(f func(*config.Site)) config.Config {
		c := base
		c.Sites = slices.Clone(base.Sites)
		f(&c.Sites[0])
		return c
	}
	off := with(func(s *config.Site) { s.Enabled = false })
	moreHost := with(func(s *config.Site) { s.Hostnames = append(slices.Clone(s.Hostnames), "b.example.com") })
	wellKnown := with(func(s *config.Site) { s.AllowWellKnown = true })
	for name, tc := range map[string]struct {
		cur, next config.Config
		want      bool
	}{
		"same":                     {base, base, false},
		"site back on":             {off, base, true},
		"site off is fine":         {base, off, false},
		"new hostname":             {base, moreHost, true},
		"hostname removed is fine": {moreHost, base, false},
		"well-known on":            {base, wellKnown, true},
	} {
		if got := restoreWeakens(tc.cur, tc.next); got != tc.want {
			t.Errorf("%s: restoreWeakens = %v, want %v", name, got, tc.want)
		}
	}
}

// Code review CR-1: going offline when the web worker then refuses the load
// still leaves the switch on: the restore keeps the stricter tunnel side.
func TestRefusedOfflineChangeStaysOffline(t *testing.T) {
	var refuse atomic.Bool
	svc := &fakeServices{webLoad: func(_ func(), m ipc.WorkerMsg) error {
		if refuse.Load() {
			return errors.New("refused by the test worker")
		}
		return worker.LoadJSON(m.Caddy)
	}}
	h := startWith(t, svc, nil, 20*time.Second)
	app := okApp(t)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	refuse.Store(true)
	_ = h.call(ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: true}, nil)
	var now ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &now); err != nil {
		t.Fatal(err)
	}
	if !now.Config.Tunnel.Offline {
		t.Fatal("a refused load undid the offline switch")
	}
}
