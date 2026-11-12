//go:build e2e

// Package e2e checks an installed SoiréeHost from the outside. It runs only on
// a throwaway CI runner with administrator rights, after
// "soireehost setup install" (plan Phase 2, docs/TEST_PLAN.md "Isolation"),
// and never on the owner's PC (machine rule).
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

const canary = "CANARY-E2E-TUNNEL-TOKEN-5d1e"

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUser               = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob          = kernel32.NewProc("IsProcessInJob")
)

func TestMain(m *testing.M) {
	if os.Getenv("SOIREEHOST_E2E") != "1" {
		fmt.Println("skipping: set SOIREEHOST_E2E=1 on a CI runner after setup install")
		os.Exit(0)
	}
	// Every test needs a running supervisor. Wait for it once and stop with
	// a clear message if it never starts, instead of each test waiting and
	// the run hitting go test's timeout.
	if err := waitSupervisor(2 * time.Minute); err != nil {
		fmt.Println("the installed supervisor never started:", err)
		fmt.Println("see the Application event log (source SoireeHost) for its reason")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func waitSupervisor(within time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(winsec.SupervisorService)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	deadline := time.Now().Add(within)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("state %d after %v", st.State, within)
		}
		time.Sleep(time.Second)
	}
}

func layout(t *testing.T) setup.Layout {
	t.Helper()
	l, err := setup.DefaultLayout()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func service(t *testing.T, name string) *mgr.Service {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Disconnect() })
	s, err := m.OpenService(name)
	if err != nil {
		t.Fatalf("service %s: %v", name, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func state(t *testing.T, name string) svc.Status {
	t.Helper()
	st, err := service(t, name).Query()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func waitState(t *testing.T, name string, want svc.State, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if st := state(t, name); st.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not reach state %d within %v (now %d)", name, want, within, state(t, name).State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func waitAllRunning(t *testing.T) {
	t.Helper()
	for _, n := range []string{winsec.SupervisorService, winsec.WebService, winsec.TunnelService} {
		waitState(t, n, svc.Running, 90*time.Second)
	}
}

func control(t *testing.T) *ipc.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		c, err := ipc.DialControl(ctx, ipc.ControlPipe, winsec.ServiceSID(winsec.SupervisorService))
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		last = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("control pipe: %v", last)
	return nil
}

func call(t *testing.T, c *ipc.Client, method string, params, out any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	return c.Call(ctx, method, params, out)
}

// S-20: the three services exist with virtual accounts, restricted SIDs,
// quoted paths, trimmed privileges, and worker descriptors that let ordinary
// users only query.
func TestServiceConfiguration(t *testing.T) {
	waitAllRunning(t)
	l := layout(t)
	for _, name := range []string{winsec.SupervisorService, winsec.WebService, winsec.TunnelService} {
		s := service(t, name)
		cfg, err := s.Config()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServiceStartName != `NT SERVICE\`+name {
			t.Errorf("%s runs as %q", name, cfg.ServiceStartName)
		}
		if cfg.SidType != windows.SERVICE_SID_TYPE_RESTRICTED {
			t.Errorf("%s SID type %d", name, cfg.SidType)
		}
		if !strings.HasPrefix(cfg.BinaryPathName, `"`+l.Exe()+`"`) {
			t.Errorf("%s binary path not quoted: %s", name, cfg.BinaryPathName)
		}
		if privs := requiredPrivileges(t, s.Handle); len(privs) != 1 || privs[0] != "SeChangeNotifyPrivilege" {
			t.Errorf("%s required privileges %v", name, privs)
		}
	}
	for _, name := range []string{winsec.WebService, winsec.TunnelService} {
		sd, err := windows.GetSecurityInfo(service(t, name).Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		s := sd.String()
		if !strings.Contains(s, "(A;;CCLCSWLORC;;;IU)") || strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;AU)") || strings.Contains(s, ";;;WD)") {
			t.Errorf("%s descriptor %s", name, s)
		}
	}
	if cfg, _ := service(t, winsec.WebService).Config(); cfg.StartType != mgr.StartManual {
		t.Errorf("web worker start type %d", cfg.StartType)
	}
}

func requiredPrivileges(t *testing.T, h windows.Handle) []string {
	t.Helper()
	var need uint32
	_ = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, nil, 0, &need)
	buf := make([]byte, need)
	if err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &buf[0], need, &need); err != nil {
		t.Fatal(err)
	}
	p := *(**uint16)(unsafe.Pointer(&buf[0])) //nolint:gosec // G103: reading the multi-string the API returned
	var out []string
	for p != nil && *p != 0 {
		s := windows.UTF16PtrToString(p)
		out = append(out, s)
		p = (*uint16)(unsafe.Add(unsafe.Pointer(p), 2*(len(s)+1))) //nolint:gosec // G103: as above
	}
	return out
}

// The installing user drives the supervisor over the pipe, and sites are
// served by the confined web worker on loopback.
func TestServesThroughInstalledServices(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "E2E-APP") }))
	defer app.Close()
	site := config.Site{ID: "app", Name: "App", Enabled: true, Hostnames: []string{"app.e2e.example"},
		Type: config.TypeProxy, Proxy: &config.Proxy{Target: app.Listener.Addr().String()}}
	if err := call(t, c, ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, "app.e2e.example"); code != 200 || body != "E2E-APP" {
		t.Fatalf("proxy site: %d %q", code, body)
	}

	// A static folder locked like one inside a user profile (only SYSTEM,
	// Administrators and this user), then granted access the way the
	// control panel does when a site is added.
	base := os.Getenv("RUNNER_TEMP")
	if base == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "e2e-site-"+randHex())
	me, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	if err := winsec.SetFolderSDDL(root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+me.SID+")"); err != nil {
		t.Fatal(err)
	}
	// before access is granted, the supervisor cannot use the folder
	locked := config.Site{ID: "locked", Name: "Locked", Enabled: true, Hostnames: []string{"locked.e2e.example"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	var ierr *ipc.Error
	if err := call(t, c, ipc.MethodSitePut, ipc.SitePutParams{Site: locked}, nil); !errors.As(err, &ierr) || ierr.Code != ipc.CodeInvalid {
		t.Fatalf("site.put on a folder SoiréeHost may not open: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("E2E-STATIC"), 0o644); err != nil { //nolint:gosec // G306: a published page
		t.Fatal(err)
	}
	if err := winsec.GrantSiteAccess(root, winsec.ServiceSID(winsec.WebService), winsec.ServiceSID(winsec.SupervisorService)); err != nil {
		t.Fatal(err)
	}
	static := config.Site{ID: "files", Name: "Files", Enabled: true, Hostnames: []string{"files.e2e.example"},
		Type: config.TypeStatic, Static: &config.Static{Root: root}}
	if err := call(t, c, ipc.MethodSitePut, ipc.SitePutParams{Site: static}, nil); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, "files.e2e.example"); code != 200 || body != "E2E-STATIC" {
		t.Fatalf("static site: %d %q", code, body)
	}

	// S-36 on the installed system: the supervisor can append to its audit
	// log under the append-only folder permissions, and the chain verifies
	var al ipc.AuditListResult
	if err := call(t, c, ipc.MethodAuditList, ipc.AuditListParams{Limit: 100}, &al); err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, e := range al.Entries {
		actions[e.Action] = true
	}
	if !al.Report.OK() || !actions["supervisor.start"] || !actions["site.put"] {
		t.Fatalf("audit log on the installed system: report %+v, actions %v", al.Report, actions)
	}
	var st ipc.StatusResult
	if err := call(t, c, ipc.MethodStatus, ipc.None{}, &st); err != nil || !st.AuditOK {
		t.Fatalf("status reports the audit log failing: %+v %v", st, err)
	}
}

func get(t *testing.T, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+config.DefaultListen+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Plan Phase 2: a second local user cannot open the pipe, cannot start or
// stop the worker services, and cannot read config or secrets (S-20, S-22,
// S-30).
func TestSecondUserLockedOut(t *testing.T) {
	waitAllRunning(t)
	name := "shtest" + randHex()[:6]
	pass := "Aa1!" + randHex() + randHex()
	if out, err := exec.CommandContext(t.Context(), "net", "user", name, pass, "/add").CombinedOutput(); err != nil { // #nosec G204 -- test user on a throwaway runner
		t.Fatalf("creating test user: %v %s", err, out)
	}
	defer func() { _ = exec.CommandContext(context.Background(), "net", "user", name, "/delete").Run() }() //nolint:gosec // G204: test user on a throwaway runner

	tok := logon(t, name, pass)
	defer func() { _ = tok.Close() }()
	l := layout(t)
	p := supervisor.Paths{Root: l.DataRoot}

	results := asUser(t, tok, func() map[string]error {
		r := map[string]error{}
		r["open control pipe"] = openPipe(ipc.ControlPipe)
		r["open web pipe"] = openPipe(ipc.WebPipe)
		r["start web worker"] = serviceAccess(winsec.WebService, windows.SERVICE_START)
		r["stop tunnel launcher"] = serviceAccess(winsec.TunnelService, windows.SERVICE_STOP)
		r["read secrets"] = readDir(p.Secrets())
		r["read config"] = readDir(p.Config())
		r["read audit log"] = readDir(p.Audit())
		return r
	})
	for what, err := range results {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Errorf("second user could %s (error: %v)", what, err)
		}
	}
	// the same user may still query a worker service's status
	if err := func() error {
		var err error
		asUser(t, tok, func() map[string]error {
			err = serviceAccess(winsec.WebService, windows.SERVICE_QUERY_STATUS)
			return nil
		})
		return err
	}(); err != nil {
		t.Errorf("second user cannot query the worker service: %v", err)
	}
}

func logon(t *testing.T, user, pass string) windows.Token {
	t.Helper()
	u, _ := windows.UTF16PtrFromString(user)
	d, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(pass)
	var tok windows.Token
	const logonInteractive, providerDefault = 2, 0
	//nolint:gosec // G103: Windows API arguments
	r, _, err := procLogonUser.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(pw)),
		logonInteractive, providerDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		t.Fatalf("logging on the test user: %v", err)
	}
	return tok
}

// asUser runs fn on a locked thread impersonating tok, then reverts.
func asUser(t *testing.T, tok windows.Token, fn func() map[string]error) map[string]error {
	t.Helper()
	out := make(chan map[string]error)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if r, _, err := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
			t.Errorf("impersonating: %v", err)
			out <- nil
			return
		}
		res := fn()
		if err := windows.RevertToSelf(); err != nil {
			panic(err)
		}
		out <- res
	}()
	return <-out
}

func openPipe(path string) error {
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err == nil {
		_ = windows.CloseHandle(h)
	}
	return err
}

func serviceAccess(name string, access uint32) error {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(m) //nolint:errcheck // test
	n, _ := windows.UTF16PtrFromString(name)
	s, err := windows.OpenService(m, n, access)
	if err == nil {
		_ = windows.CloseServiceHandle(s)
	}
	return err
}

func readDir(path string) error {
	_, err := os.ReadDir(path)
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// S-21 on the real services: each worker process is in a job object and
// cannot start a child.
func TestWorkersAreConfined(t *testing.T) {
	waitAllRunning(t)
	for _, name := range []string{winsec.WebService, winsec.TunnelService} {
		pid := state(t, name).ProcessId
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var in int32
		r, _, err := procIsProcessInJob.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&in))) //nolint:gosec // G103: Windows API arguments
		_ = windows.CloseHandle(h)
		if r == 0 {
			t.Fatalf("%s: IsProcessInJob: %v", name, err)
		}
		if in == 0 {
			t.Errorf("%s is not in a job object", name)
		}
	}
}

// S-40 canary sweep (plan section 10): a tunnel token set over the pipe never
// appears in clear in files, logs or process command lines.
func TestTunnelTokenCanary(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	err := call(t, c, ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canary}, nil)
	var e *ipc.Error
	if errors.As(err, &e) && e.Code == ipc.CodeConfirmationRequired {
		err = call(t, c, ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canary, Confirm: true}, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	l := layout(t)
	_ = filepath.WalkDir(l.DataRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(canary)) { //nolint:gosec // G304: sweeping SoiréeHost's own data folder
			t.Errorf("%s contains the token in clear", p)
		}
		return nil
	})
	out, err := exec.CommandContext(t.Context(), "powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Process | ForEach-Object { $_.CommandLine }").Output()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(canary)) {
		t.Error("the token appears in a process command line")
	}
}

// Plan Phase 2: killing the supervisor's process ends both workers within
// five seconds; Windows recovery then restarts everything.
func TestKillingSupervisorEndsWorkers(t *testing.T) {
	waitAllRunning(t)
	pid := state(t, winsec.SupervisorService).ProcessId
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		t.Fatal(err)
	}
	_ = windows.CloseHandle(h)
	waitState(t, winsec.WebService, svc.Stopped, 5*time.Second)
	waitState(t, winsec.TunnelService, svc.Stopped, 5*time.Second)
	waitAllRunning(t)
}

// Plan Phase 2: stopping the supervisor stops both workers.
func TestStoppingSupervisorEndsWorkers(t *testing.T) {
	waitAllRunning(t)
	if _, err := service(t, winsec.SupervisorService).Control(svc.Stop); err != nil {
		t.Fatal(err)
	}
	waitState(t, winsec.SupervisorService, svc.Stopped, 30*time.Second)
	waitState(t, winsec.WebService, svc.Stopped, 10*time.Second)
	waitState(t, winsec.TunnelService, svc.Stopped, 10*time.Second)
	if err := service(t, winsec.SupervisorService).Start(); err != nil {
		t.Fatal(err)
	}
	waitAllRunning(t)
}

// S-22: if the secrets folder becomes writable by Users, the supervisor
// refuses to start; once fixed, it starts again.
func TestACLDriftRefused(t *testing.T) {
	waitAllRunning(t)
	sup := service(t, winsec.SupervisorService)
	if _, err := sup.Control(svc.Stop); err != nil {
		t.Fatal(err)
	}
	waitState(t, winsec.SupervisorService, svc.Stopped, 30*time.Second)

	p := supervisor.Paths{Root: layout(t).DataRoot}
	enablePrivilege(t, "SeRestorePrivilege")
	drifted := winsec.SecretsFolderSDDL(winsec.ServiceSID(winsec.SupervisorService)) + "(A;OICI;0x1301bf;;;" + winsec.SIDUsers + ")"
	setDACL(t, p.Secrets(), drifted)
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if st := state(t, winsec.SupervisorService); st.State == svc.Running {
		t.Error("supervisor runs with a secrets folder writable by Users")
	}
	if st := state(t, winsec.WebService); st.State == svc.Running {
		t.Error("web worker started by a supervisor that should have refused to run")
	}

	_, _ = sup.Control(svc.Stop)
	waitState(t, winsec.SupervisorService, svc.Stopped, 60*time.Second)
	setDACL(t, p.Secrets(), winsec.SecretsFolderSDDL(winsec.ServiceSID(winsec.SupervisorService)))
	if err := sup.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		t.Fatal(err)
	}
	waitAllRunning(t)
}

func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tok.Close() }()
	var luid windows.LUID
	n, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		t.Fatal(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// setDACL rewrites a folder's DACL with SeRestorePrivilege, which an elevated
// administrator holds, without taking ownership.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(path)
	// FILE_FLAG_BACKUP_SEMANTICS with WRITE_DAC uses SeRestorePrivilege
	h, err := windows.CreateFile(p, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("opening %s for WRITE_DAC: %v", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatalf("setting DACL of %s: %v", path, err)
	}
}
