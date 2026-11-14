package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

// dataRoot holds every test's data folder. Caddy keeps a log file open for
// the life of the process once opened, so per-test temporary folders could
// not be removed; this one is cleared at the start of each run.
var dataRoot string

func TestMain(m *testing.M) {
	dataRoot = filepath.Join(os.TempDir(), "soireehost-supervisor-test")
	_ = os.RemoveAll(dataRoot)
	os.Exit(m.Run())
}

const canary = "CANARY-TUNNEL-TOKEN-7f3a9c"

// fakeServices runs the workers in-process: the web worker with real Caddy,
// the tunnel launcher as a stand-in that records the token it receives.
type fakeServices struct {
	t       *testing.T
	pipes   Pipes
	sup     string
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	exited  map[string]chan struct{}
	starts  map[string]int
	tokens  chan string

	// webLoad, if set, replaces the web worker's Load; die ends the worker
	// as if its process died (the pipe closes without an answer).
	webLoad func(die func(), m ipc.WorkerMsg) error
	// rawWeb, if set, replaces the whole web agent.
	rawWeb func(ctx context.Context, pipe, sid string)
}

func (f *fakeServices) startCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts[name]
}

func (f *fakeServices) Start(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, running := f.cancels[name]; running {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	f.cancels[name], f.exited[name] = cancel, done
	f.starts[name]++
	o := ipc.AgentOptions{SupervisorSID: f.sup, Version: "test", DialTimeout: 10 * time.Second}
	body := func() { _ = ipc.RunAgent(ctx, o) }
	switch name {
	case winsec.WebService:
		o.Pipe, o.Role = f.pipes.Web, ipc.RoleWeb
		load, raw := f.webLoad, f.rawWeb
		die := func() { cancel(); time.Sleep(200 * time.Millisecond) }
		o.Load = func(m ipc.WorkerMsg) error {
			if load != nil {
				return load(die, m)
			}
			return worker.LoadJSON(m.Caddy)
		}
		o.Stop = func() { _ = worker.Stop() }
		if raw != nil {
			body = func() { raw(ctx, f.pipes.Web, f.sup) }
		}
	case winsec.TunnelService:
		o.Pipe, o.Role = f.pipes.Tunnel, ipc.RoleTunnel
		o.Load = func(m ipc.WorkerMsg) error { f.tokens <- m.Token; return nil }
	default:
		return fmt.Errorf("unknown service %s", name)
	}
	go func() {
		defer close(done)
		body()
		f.mu.Lock()
		delete(f.cancels, name)
		f.mu.Unlock()
	}()
	return nil
}

func (f *fakeServices) Stop(name string) error {
	f.mu.Lock()
	cancel := f.cancels[name]
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// kill ends a worker as if its process died.
func (f *fakeServices) kill(name string) {
	f.mu.Lock()
	cancel, done := f.cancels[name], f.exited[name]
	f.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (f *fakeServices) running(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.cancels[name]
	return ok
}

type harness struct {
	t      *testing.T
	sup    *Supervisor
	svc    *fakeServices
	client *ipc.Client
	listen string
	paths  Paths
	cancel context.CancelFunc
	done   chan error
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func start(t *testing.T, checkRoot func(string) (string, error)) *harness {
	t.Helper()
	return startWith(t, &fakeServices{}, checkRoot, 20*time.Second)
}

// startWith starts a supervisor whose workers are svc (its hooks set by the
// caller) and whose loads time out after loadTimeout.
func startWith(t *testing.T, svc *fakeServices, checkRoot func(string) (string, error), loadTimeout time.Duration) *harness {
	t.Helper()
	me, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	id := randHex()
	pipes := Pipes{
		Control: `\\.\pipe\soireehost-test-ctl-` + id,
		Web:     `\\.\pipe\soireehost-test-web-` + id,
		Tunnel:  `\\.\pipe\soireehost-test-tun-` + id,
	}
	paths := Paths{Root: filepath.Join(dataRoot, id)}
	for _, d := range []string{paths.Config(), paths.Secrets(), paths.Audit(), paths.WebLogs()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The pipe-name folders and config get their installed descriptors, so
	// publishing runs under config's OWNER RIGHTS entry as in the service
	// (it refused descriptors passed at creation; isolation job, PR 3).
	// Config is locked last: OWNER RIGHTS would keep the test account from
	// setting the descriptors of folders it then creates inside it.
	for _, f := range []string{ipc.ControlPipeFile, ipc.WebPipeFile, ipc.TunnelPipeFile} {
		if err := winsec.CreateFolderSDDL(ipc.PipeFileFolder(paths.Root, f), winsec.PipeNameFolderSDDL(me.SID, me.SID)); err != nil {
			t.Fatal(err)
		}
	}
	if err := winsec.ForceSDDL(paths.Config(), winsec.ConfigFolderSDDL(me.SID)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ControlUsersFile(), []byte(`{"users":["`+me.SID+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.t, svc.pipes, svc.sup = t, pipes, me.SID
	svc.cancels, svc.exited = map[string]context.CancelFunc{}, map[string]chan struct{}{}
	svc.starts, svc.tokens = map[string]int{}, make(chan string, 10)
	if checkRoot == nil {
		loc, err := sitecheck.DefaultLocations()
		if err != nil {
			t.Fatal(err)
		}
		checkRoot = func(r string) (string, error) { return sitecheck.CheckRoot(r, loc) }
	}
	sup, err := New(Options{
		Paths: paths, Identity: Identity{Supervisor: me.SID, Web: me.SID, Tunnel: me.SID},
		Pipes: pipes, Services: svc, Version: "test", CheckRoot: checkRoot,
		WorkerStartTimeout: 10 * time.Second, LoadTimeout: loadTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, sup: sup, svc: svc, paths: paths, cancel: cancel, done: make(chan error, 1),
		listen: fmt.Sprintf("127.0.0.1:%d", freePort(t))}
	// the first load must use this test's port, not the default 8787
	cfg := config.Default()
	cfg.Listen = h.listen
	if _, err := sup.store.Save(cfg, "test", "listen"); err != nil {
		t.Fatal(err)
	}
	go func() { h.done <- sup.Run(ctx) }()
	t.Cleanup(h.stop)

	deadline := time.Now().Add(10 * time.Second)
	for {
		dctx, dcancel := context.WithTimeout(t.Context(), 2*time.Second)
		c, err := ipc.DialControl(dctx, pipes.Control, me.SID)
		dcancel()
		if err == nil {
			h.client = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control pipe never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.waitWorkers(StateRunning)
	return h
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	if h.client != nil {
		_ = h.client.Close()
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("supervisor stopped with: %v", err)
		}
	case <-time.After(15 * time.Second):
		h.t.Error("supervisor did not stop")
	}
}

func (h *harness) call(method string, params, out any) error {
	ctx, cancel := context.WithTimeout(h.t.Context(), 30*time.Second)
	defer cancel()
	return h.client.Call(ctx, method, params, out)
}

func (h *harness) waitWorkers(want string) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var st ipc.StatusResult
		if err := h.call(ipc.MethodStatus, ipc.None{}, &st); err == nil {
			all := true
			for _, w := range st.Workers {
				all = all && w.State == want
			}
			if all {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("workers never reached %s", want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (h *harness) proxySite(id, target string) config.Site {
	return config.Site{ID: id, Name: id, Enabled: true, Hostnames: []string{id + ".example.com"},
		Type: config.TypeProxy, Proxy: &config.Proxy{Target: target}}
}

func get(t *testing.T, addr, host, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestControlFlowServesSites(t *testing.T) {
	h := start(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "FROM-APP") }))
	defer app.Close()

	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, &res); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, h.listen, "app.example.com", "/"); code != 200 || body != "FROM-APP" {
		t.Fatalf("proxy site: %d %q", code, body)
	}

	root := testutil.SiteDir(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("FROM-FOLDER"), 0o600); err != nil {
		t.Fatal(err)
	}
	site := config.Site{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, &res); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, h.listen, "blog.example.com", "/"); code != 200 || body != "FROM-FOLDER" {
		t.Fatalf("static site: %d %q", code, body)
	}

	if err := h.call(ipc.MethodSiteSetEnabled, ipc.SiteEnabledParams{ID: "app", Enabled: false}, &res); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, h.listen, "app.example.com", "/"); code != 404 {
		t.Fatalf("disabled site answered %d", code)
	}
	if err := h.call(ipc.MethodSiteRemove, ipc.SiteIDParams{ID: "app"}, &res); err != nil {
		t.Fatal(err)
	}
	var e *ipc.Error
	if err := h.call(ipc.MethodSiteRemove, ipc.SiteIDParams{ID: "app"}, nil); !errors.As(err, &e) || e.Code != ipc.CodeNotFound {
		t.Fatalf("removing a missing site: %v", err)
	}

	var hist ipc.HistoryResult
	if err := h.call(ipc.MethodConfigHistory, ipc.None{}, &hist); err != nil || len(hist.Revisions) < 4 || hist.LastGood != hist.Revisions[0].Revision {
		t.Fatalf("history %+v, %v", hist, err)
	}
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: 2}, &res); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, h.listen, "app.example.com", "/"); code != 200 || body != "FROM-APP" {
		t.Fatalf("after rollback to revision 2: %d %q", code, body)
	}

	var al ipc.AuditListResult
	if err := h.call(ipc.MethodAuditList, ipc.AuditListParams{Limit: 100}, &al); err != nil || !al.Report.OK() {
		t.Fatalf("audit %+v, %v", al.Report, err)
	}
	actions := map[string]bool{}
	for _, e := range al.Entries {
		actions[e.Action] = true
	}
	for _, a := range []string{"supervisor.start", "site.put", "site.set_enabled", "site.remove", "config.rollback"} {
		if !actions[a] {
			t.Errorf("no %s entry in the audit log", a)
		}
	}
}

// S-11 through the control API: a blocked folder is refused before saving.
func TestSitePutRefusesBlockedFolder(t *testing.T) {
	h := start(t, nil)
	loc, _ := sitecheck.DefaultLocations()
	site := config.Site{ID: "win", Name: "Win", Enabled: true, Hostnames: []string{"win.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: loc.Windows}}
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
		t.Fatalf("Windows folder: %v", err)
	}
}

// ADR-0006: a folder the web worker may not read is refused before saving,
// with a message that says how to fix it.
func TestSitePutRefusesUnreadableFolder(t *testing.T) {
	h := start(t, nil)
	h.sup.opts.WorkerCanRead = func(string) (bool, error) { return false, nil }
	root := testutil.SiteDir(t)
	site := config.Site{ID: "x", Name: "X", Enabled: true, Hostnames: []string{"x.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); !errors.As(err, &e) || !strings.Contains(e.Message, "not allowed to read") {
		t.Fatalf("unreadable folder: %v", err)
	}
	var cur ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &cur); err != nil || len(cur.Config.Sites) != 0 {
		t.Fatalf("refused site was saved: %+v %v", cur.Config.Sites, err)
	}
}

// S-32: a LAN target needs confirmation and is audited as weakening.
func TestWeakeningNeedsConfirmation(t *testing.T) {
	h := start(t, nil)
	site := h.proxySite("nas", "192.168.1.20:5000")
	site.Proxy.AllowLAN = true
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired {
		t.Fatalf("unconfirmed LAN target: %v", err)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirm: true}, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Error("no warning for a LAN target")
	}
	var al ipc.AuditListResult
	_ = h.call(ipc.MethodAuditList, ipc.AuditListParams{}, &al)
	found := false
	for _, e := range al.Entries {
		found = found || (e.Action == "site.put" && e.Detail["weakening"] == "allow_lan")
	}
	if !found {
		t.Error("weakening change not audited")
	}
}

// S-41: a config the web worker refuses is replaced by the last good one.
func TestRefusedConfigIsRolledBack(t *testing.T) {
	missing := filepath.Join(testutil.SiteDir(t), "gone")
	h := start(t, func(r string) (string, error) {
		if strings.HasSuffix(r, "gone") {
			return r, nil // pretend the folder passed the check, then vanished
		}
		loc, _ := sitecheck.DefaultLocations()
		return sitecheck.CheckRoot(r, loc)
	})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	defer app.Close()
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, &res); err != nil {
		t.Fatal(err)
	}
	good := res.Revision
	bad := config.Site{ID: "bad", Name: "Bad", Enabled: true, Hostnames: []string{"bad.example.com"},
		Type: config.TypeStatic, Static: &config.Static{Root: missing}}
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: bad}, nil); !errors.As(err, &e) || !strings.Contains(e.Message, "previous settings were restored") {
		t.Fatalf("refused config: %v", err)
	}
	var cur ipc.ConfigResult
	if err := h.call(ipc.MethodConfigGet, ipc.None{}, &cur); err != nil {
		t.Fatal(err)
	}
	if len(cur.Config.Sites) != 1 || cur.Config.Sites[0].ID != "app" || h.sup.store.LastGood() != cur.Revision {
		t.Fatalf("after rollback: revision %d (good %d, was %d), sites %v", cur.Revision, h.sup.store.LastGood(), good, cur.Config.Sites)
	}
	if code, body := get(t, h.listen, "app.example.com", "/"); code != 200 || body != "OK" {
		t.Fatalf("site down after rollback: %d %q", code, body)
	}
}

// S-35, S-40, S-32: the tunnel token is write-only, reaches only the tunnel
// worker, needs confirmation to replace, and never appears in clear on disk.
func TestTunnelTokenWriteOnly(t *testing.T) {
	h := start(t, nil)
	var st ipc.SecretStatusResult
	if err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canary}, &st); err != nil {
		t.Fatal(err)
	}
	if !st.Secrets[0].Set {
		t.Fatal("not set")
	}
	select {
	case tok := <-h.svc.tokens:
		if tok != canary {
			t.Fatalf("tunnel worker got %q", tok)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel worker never got the token")
	}
	var e *ipc.Error
	if err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canary + "2"}, nil); !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired {
		t.Fatalf("replacing without confirm: %v", err)
	}
	if err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canary + "2", Confirm: true}, nil); err != nil {
		t.Fatal(err)
	}
	var status ipc.SecretStatusResult
	if err := h.call(ipc.MethodSecretStatus, ipc.None{}, &status); err != nil || !status.Secrets[0].Set {
		t.Fatalf("status %+v %v", status, err)
	}
	// canary sweep (plan section 10): nothing on disk holds the token in
	// clear, and the sweep read the secrets, config and audit files (GOE-12)
	seen := testutil.SweepFiles(t, h.paths.Root, []byte("CANARY-TUNNEL"), nil)
	for _, dir := range []string{h.paths.Secrets(), h.paths.Config(), h.paths.Audit()} {
		if testutil.Under(seen, dir) == 0 {
			t.Errorf("the canary sweep read nothing in %s", dir)
		}
	}
}

// ADR-0001: a dead worker is restarted and brought up to date.
func TestWorkerRestarted(t *testing.T) {
	h := start(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }))
	defer app.Close()
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: h.proxySite("app", app.Listener.Addr().String())}, nil); err != nil {
		t.Fatal(err)
	}
	h.svc.kill(winsec.WebService)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if code, _ := get(t, h.listen, "app.example.com", "/"); code == 200 {
			h.svc.mu.Lock()
			n := h.svc.starts[winsec.WebService]
			h.svc.mu.Unlock()
			if n < 2 {
				t.Fatalf("served without a restart? starts=%d", n)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("web worker not restarted")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Plan Phase 2: stopping the supervisor ends both workers.
func TestStoppingSupervisorEndsWorkers(t *testing.T) {
	h := start(t, nil)
	if !h.svc.running(winsec.WebService) || !h.svc.running(winsec.TunnelService) {
		t.Fatal("workers not running")
	}
	h.stop()
	deadline := time.Now().Add(5 * time.Second)
	for h.svc.running(winsec.WebService) || h.svc.running(winsec.TunnelService) {
		if time.Now().After(deadline) {
			t.Fatal("workers still running 5 seconds after the supervisor stopped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// S-30: who may use the control pipe.
func TestAuthorize(t *testing.T) {
	s := &Supervisor{users: []string{"S-1-5-21-1-2-3-1001"}}
	cases := map[winsec.Caller]bool{
		{SID: winsec.SIDSystem}:                  true,
		{SID: "S-1-5-21-1-2-3-500", Admin: true}: true,
		{SID: "S-1-5-21-1-2-3-1001"}:             true,
		{SID: "S-1-5-21-1-2-3-1002"}:             false,
		{SID: "S-1-5-21-1-2-3-500"}:              false,
		{SID: winsec.SIDNetwork}:                 false,
	}
	for c, want := range cases {
		if got := s.authorize(c); got != want {
			t.Errorf("authorize(%+v) = %v, want %v", c, got, want)
		}
	}
}

func TestReadControlUsers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "u.json")
	if users, err := readControlUsers(p); err != nil || users != nil {
		t.Fatalf("missing file: %v %v", users, err)
	}
	// SE-05: entries go into the control pipe's descriptor, so only one
	// user account's SID, in canonical form, is accepted
	for _, bad := range []string{
		`{"users":["Everyone"]}`, `{"users":"x"}`, `not json`,
		`{"users":["S-1-5-18)(A;;GA;;;WD"]}`,
		`{"users":["S-1-5-21-1-2-3-1001)(A;;GA;;;WD"]}`,
		`{"users":["S-1-1-0"]}`, `{"users":["S-1-5-32-545"]}`, `{"users":["S-1-5-11"]}`, `{"users":["S-1-5-18"]}`,
		`{"users":["s-1-5-21-1-2-3-1001"]}`, `{"users":["S-1-5-21-1-2-3-01001"]}`,
	} {
		_ = os.WriteFile(p, []byte(bad), 0o600)
		if _, err := readControlUsers(p); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, good := range []string{"S-1-5-21-1-2-3-1001", "S-1-12-1-1-2-3-4"} {
		_ = os.WriteFile(p, []byte(`{"users":["`+good+`"]}`), 0o600)
		if users, err := readControlUsers(p); err != nil || len(users) != 1 || users[0] != good {
			t.Errorf("%s: %v %v", good, users, err)
		}
	}
}

// S-32 (owner decision of 13 Nov 2026, review finding R-04): rolling back
// to a revision that forwards to a LAN device the current settings do not
// needs the same confirmation, and is audited as weakening.
func TestRollbackToLANNeedsConfirmation(t *testing.T) {
	h := start(t, nil)
	site := h.proxySite("nas", "192.168.1.20:5000")
	site.Proxy.AllowLAN = true
	var withLAN ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirm: true}, &withLAN); err != nil {
		t.Fatal(err)
	}
	if err := h.call(ipc.MethodSiteRemove, ipc.SiteIDParams{ID: "nas"}, nil); err != nil {
		t.Fatal(err)
	}
	var e *ipc.Error
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: withLAN.Revision}, nil); !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired {
		t.Fatalf("unconfirmed rollback to a LAN target: %v", err)
	}
	if _, ids := siteIDs(h); len(ids) != 0 {
		t.Fatalf("the unconfirmed rollback was applied: %v", ids)
	}
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: withLAN.Revision, Confirm: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ids := siteIDs(h); len(ids) != 1 || ids[0] != "nas" {
		t.Fatalf("confirmed rollback not applied: %v", ids)
	}
	var al ipc.AuditListResult
	_ = h.call(ipc.MethodAuditList, ipc.AuditListParams{}, &al)
	found := false
	for _, e := range al.Entries {
		found = found || (e.Action == "config.rollback" && e.Detail["weakening"] == "allow_lan")
	}
	if !found {
		t.Error("weakening rollback not audited")
	}
	// back to a revision whose LAN target is already in force: no question
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: withLAN.Revision}, nil); err != nil {
		t.Fatalf("rollback with no new LAN target: %v", err)
	}
}
