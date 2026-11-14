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

// siteIDs returns the current revision and the IDs of its sites.
func siteIDs(h *harness) (uint64, []string) {
	h.t.Helper()
	var cur ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &cur); err != nil {
		h.t.Fatal(err)
	}
	var ids []string
	for _, s := range cur.Config.Sites {
		ids = append(ids, s.ID)
	}
	return cur.Revision, ids
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
	if _, ids := siteIDs(h); slices.Contains(ids, "crash") {
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
	if _, ids := siteIDs(h); slices.Contains(ids, "slow") {
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
	_, ids := siteIDs(h)
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
	if _, ids := siteIDs(h); slices.Contains(ids, "refuse") || err == nil {
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
		wc := ipc.NewWorkerConn(conn)
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
	h := start(t, nil)
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
