//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/tunnel"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// canaryToken is a well-formed tunnel token (S-50) for a tunnel that does
// not exist. cloudflared runs with it and fails to connect, which is enough
// to sweep its command line and logs for the token.
func canaryToken(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"a": "0123456789abcdef0123456789abcdef",
		"t": "6ff42ae2-765d-4adf-8112-31c55c1551ef",
		"s": base64.StdEncoding.EncodeToString([]byte(canary + "-0123456789abcdef")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func status(t *testing.T, c *ipc.Client) ipc.StatusResult {
	t.Helper()
	var st ipc.StatusResult
	if err := call(t, c, ipc.MethodStatus, ipc.None{}, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// waitTunnel polls status until ok holds for the tunnel view of kind/site.
func waitTunnel(t *testing.T, c *ipc.Client, within time.Duration, what string, ok func(ipc.TunnelStatus) bool) ipc.TunnelStatus {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		st := status(t, c)
		if ok(st.Tunnel) {
			return st.Tunnel
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; tunnel status %+v", what, st.Tunnel)
		}
		time.Sleep(time.Second)
	}
}

func quickView(ts ipc.TunnelStatus, site string) (ipc.TunnelView, bool) {
	for _, v := range ts.Tunnels {
		if v.Kind == ipc.TunnelKindQuick && v.SiteID == site {
			return v, true
		}
	}
	return ipc.TunnelView{}, false
}

// S-23, S-71: setup unpacked the pinned cloudflared into the program folder.
func TestCloudflaredInstalled(t *testing.T) {
	b, err := os.ReadFile(layout(t).Cloudflared())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != tunnel.CloudflaredSHA256 {
		t.Fatalf("installed cloudflared.exe has hash %s, pin %s", got, tunnel.CloudflaredSHA256)
	}
}

// S-02: setup added inbound block rules for both programs and no rule that
// allows inbound traffic to either.
func TestFirewallBlockRules(t *testing.T) {
	l := layout(t)
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$progs = @('%s', '%s')
$out = @()
foreach ($f in Get-NetFirewallApplicationFilter) {
  if ($progs -notcontains $f.Program) { continue }
  $r = $f | Get-NetFirewallRule
  $out += "$($r.DisplayName)|$($r.Direction)|$($r.Action)|$($r.Enabled)|$($f.Program)"
}
$out -join "`+"`n"+`"`, l.Exe(), l.Cloudflared())
	out, err := exec.CommandContext(t.Context(), "powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput() //nolint:gosec // G204: fixed script with the install paths
	if err != nil {
		t.Fatalf("listing firewall rules: %v\n%s", err, out)
	}
	lines := strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(out)), " ", "_"))
	t.Logf("rules for SoiréeHost programs:\n%s", out)
	blocked := map[string]bool{}
	for _, line := range lines {
		f := strings.Split(line, "|")
		if len(f) != 5 {
			t.Fatalf("unexpected line %q", line)
		}
		if f[2] == "Allow" && f[1] == "Inbound" {
			t.Errorf("an inbound allow rule exists for %s: %s", f[4], f[0])
		}
		if f[1] == "Inbound" && f[2] == "Block" && f[3] == "True" {
			blocked[strings.ReplaceAll(f[4], "_", " ")] = true
		}
	}
	for _, p := range []string{l.Exe(), l.Cloudflared()} {
		if !blocked[p] {
			t.Errorf("no enabled inbound block rule for %s", p)
		}
	}
}

// publishTestSite creates a static site in a folder the web worker may read
// and returns its id.
func publishTestSite(t *testing.T, c *ipc.Client, body string) string {
	t.Helper()
	base := os.Getenv("RUNNER_TEMP")
	if base == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "e2e-share-"+randHex())
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // G301: a published folder
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(body), 0o644); err != nil { //nolint:gosec // G306: a published page
		t.Fatal(err)
	}
	if err := winsec.GrantSiteAccess(root, winsec.ServiceSID(winsec.WebService), winsec.ServiceSID(winsec.SupervisorService)); err != nil {
		t.Fatal(err)
	}
	id := "share-" + randHex()[:6]
	site := config.Site{ID: id, Name: "Share", Enabled: true, Type: config.TypeStatic, Static: &config.Static{Root: root}}
	if err := call(t, c, ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	return id
}

// Plan Phase 3: a site opens over the internet through a quick share link
// (and, when the run was started for it, stays up for the owner's phone);
// the share's port answers 404 for any other hostname (S-06); and while it
// runs, no SoiréeHost or cloudflared process listens anywhere but loopback
// (S-01, the netstat check and the CI stand-in for the second-machine port
// scan, owner decision of 14 Nov 2026).
func TestQuickShareOverInternet(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	const page = "SOIREEHOST-PHASE3-QUICK-SHARE"
	id := publishTestSite(t, c, page)
	var res ipc.ConfigResult
	if err := call(t, c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id}, &res); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = call(t, c, ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id}, nil) })
	var port int
	for _, s := range res.Config.Sites {
		if s.ID == id && s.QuickShare != nil {
			port = s.QuickShare.Port
		}
	}
	if port == 0 {
		t.Fatalf("no quick share port in %+v", res.Config.Sites)
	}
	ts := waitTunnel(t, c, 3*time.Minute, "a quick share link", func(ts ipc.TunnelStatus) bool {
		v, ok := quickView(ts, id)
		return ok && v.URL != "" && v.State == ipc.TunnelConnected
	})
	v, _ := quickView(ts, id)
	if !v.Temporary || v.Label != ipc.QuickShareLabel || !strings.HasSuffix(v.URL, ".trycloudflare.com") {
		t.Fatalf("view %+v (S-51)", v)
	}
	host := strings.TrimPrefix(v.URL, "https://")

	// over the internet, with TLS verified as usual; a new name can take a
	// little while to resolve
	deadline := time.Now().Add(3 * time.Minute)
	for {
		code, body, err := fetch(t, v.URL)
		if err == nil && code == 200 && body == page {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the quick share link never served the site: %d %q %v", code, body, err)
		}
		time.Sleep(3 * time.Second)
	}

	// S-06 on the share's own port
	share := "127.0.0.1:" + strconv.Itoa(port)
	if code, body := getAt(t, share, host); code != 200 || body != page {
		t.Errorf("share port, its own host: %d %q", code, body)
	}
	for _, other := range []string{"other.trycloudflare.com", "app.e2e.example", share, "localhost"} {
		if code, body := getAt(t, share, other); code != 404 || strings.Contains(body, page) {
			t.Errorf("share port, Host %q: %d %q", other, code, body)
		}
	}

	checkListeners(t)

	if n, _ := strconv.Atoi(os.Getenv("SOIREEHOST_PHONE_MINUTES")); n > 0 {
		n = min(n, 30)
		// a GitHub annotation, shown on the run's page, so the owner can open
		// the link on a phone over mobile data (plan Phase 3)
		fmt.Printf("::notice title=Quick share link for the phone check::Open %s on a phone over mobile data. It shows %s and stays up for %d minutes.\n", v.URL, page, n)
		t.Logf("phone check: %s for %d minutes", v.URL, n)
		time.Sleep(time.Duration(n) * time.Minute)
	}
}

func fetch(t *testing.T, url string) (int, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

func getAt(t *testing.T, addr, host string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ourProcesses lists the process ids of the three services and every
// cloudflared.exe.
func ourProcesses(t *testing.T) map[uint32]string {
	t.Helper()
	pids := map[uint32]string{}
	for _, n := range []string{winsec.SupervisorService, winsec.WebService, winsec.TunnelService} {
		if pid := state(t, n).ProcessId; pid != 0 {
			pids[pid] = n
		}
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), tunnel.ExeName) {
			pids[pe.ProcessID] = tunnel.ExeName
		}
	}
	return pids
}

// checkListeners is the Phase 3 exposure check: every socket of every
// SoiréeHost and cloudflared process is a TCP listener on 127.0.0.1 or ::1
// (netstat), and a TCP connect scan of every port on each of this machine's
// other addresses finds none of their ports open.
func checkListeners(t *testing.T) {
	t.Helper()
	pids := ourProcesses(t)
	sawCloudflared := false
	ours := map[uint16]string{}
	for pid, name := range pids {
		if name == tunnel.ExeName {
			sawCloudflared = true
		}
		eps, err := winsec.EndpointsOf(pid)
		if err != nil {
			t.Fatalf("%s (%d): %v", name, pid, err)
		}
		for _, ep := range eps {
			ours[ep.Addr.Port()] = name
			if ep.Proto != "tcp" {
				t.Errorf("%s (%d) has a %s socket on %s", name, pid, ep.Proto, ep.Addr)
			}
		}
		if err := winsec.CheckLoopbackOnly(eps); err != nil {
			t.Errorf("%s (%d): %v", name, pid, err)
		}
		t.Logf("%s (%d) sockets: %v", name, pid, eps)
	}
	if !sawCloudflared {
		t.Error("no cloudflared process was running during the check")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var targets []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		targets = append(targets, ipn.IP.String())
	}
	if len(targets) == 0 {
		t.Fatal("no non-loopback address to scan")
	}
	for _, ip := range targets {
		open := scan(t, ip)
		t.Logf("open TCP ports on %s: %v", ip, open)
		for _, p := range open {
			if name, ok := ours[uint16(p)]; ok { //nolint:gosec // G115: ports are 1..65535
				t.Errorf("port %d on %s is open and belongs to %s", p, ip, name)
			}
		}
	}
}

// scan tries a TCP connection to every port of ip and returns the open ones.
func scan(t *testing.T, ip string) []int {
	t.Helper()
	ports := make(chan int)
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	for range 512 {
		wg.Go(func() {
			for p := range ports {
				conn, err := d.DialContext(t.Context(), "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
				if err == nil {
					_ = conn.Close()
					mu.Lock()
					open = append(open, p)
					mu.Unlock()
				}
			}
		})
	}
	for p := 1; p <= 65535; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()
	slices.Sort(open)
	return open
}

// Plan Phase 3 and S-23: a cloudflared.exe changed after install is refused
// at its next launch, and status says Repair is needed; once the original
// is back, the tunnel runs again.
func TestTamperedCloudflaredRefused(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	id := publishTestSite(t, c, "TAMPER-CHECK")
	if err := call(t, c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = call(t, c, ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id}, nil) })
	waitTunnel(t, c, 2*time.Minute, "the share running", func(ts ipc.TunnelStatus) bool {
		v, ok := quickView(ts, id)
		return ok && v.State != ipc.TunnelStarting
	})
	// offline stops every cloudflared, so the file can be changed
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: true}, nil); err != nil {
		t.Fatal(err)
	}
	waitTunnel(t, c, time.Minute, "no tunnels while offline", func(ts ipc.TunnelStatus) bool { return len(ts.Tunnels) == 0 })
	path := layout(t).Cloudflared()
	orig, err := os.ReadFile(path) //nolint:gosec // G304: the installed cloudflared.exe
	if err != nil {
		t.Fatal(err)
	}
	// the launcher holds the file open while it hashes it, so a write can
	// briefly meet a sharing violation
	write := func(b []byte) error {
		var err error
		for range 60 {
			if err = os.WriteFile(path, b, 0o755); err == nil { //nolint:gosec // G306: the program file
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return err
	}
	restore := func() {
		if err := write(orig); err != nil {
			t.Errorf("restoring cloudflared.exe: %v", err)
		}
	}
	t.Cleanup(restore)
	if err := write(append(append([]byte{}, orig...), 0)); err != nil {
		t.Fatal(err)
	}
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	ts := waitTunnel(t, c, time.Minute, "repair needed", func(ts ipc.TunnelStatus) bool { return ts.RepairNeeded })
	if !slices.ContainsFunc(ts.Warnings, func(w string) bool { return strings.Contains(w, "Run Repair") }) {
		t.Errorf("warnings %q", ts.Warnings)
	}
	if procs := ourProcesses(t); slices.Contains(slices.Collect(maps.Values(procs)), tunnel.ExeName) {
		t.Error("a cloudflared process runs although the file was changed")
	}
	restore()
	waitTunnel(t, c, 3*time.Minute, "the tunnel back after the repair", func(ts ipc.TunnelStatus) bool { return !ts.RepairNeeded })
}

// S-50 on the installed system: anything but a tunnel token is refused.
func TestOnlyTunnelTokensAccepted(t *testing.T) {
	waitAllRunning(t)
	c := control(t)
	var e *ipc.Error
	err := call(t, c, ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: "1234567890abcdef1234567890abcdef12345", Confirm: true}, nil)
	if !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
		t.Fatalf("a Global API Key was not refused: %v", err)
	}
}
