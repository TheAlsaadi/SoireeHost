//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/tunnel"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// TestOutboundTraffic is the S-42 traffic capture (ADR-0004): while a site is
// live through quick share and an update check runs, a Windows network trace
// records every TCP and UDP send with its process id. The web worker and
// the tunnel launcher reach nothing but loopback; cloudflared reaches only
// Cloudflare; the supervisor reaches only GitHub, on port 443. Name lookups
// (port 53) are allowed to both, as no connection works without them. The ranges
// come from Cloudflare's and GitHub's own published lists.
func TestOutboundTraffic(t *testing.T) {
	if os.Getenv("SOIREEHOST_S42_E2E") != "1" {
		t.Skip("set SOIREEHOST_S42_E2E=1 on the CI runner")
	}
	waitAllRunning(t)
	cloudflare := fetchRanges(t, "https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
	github := githubRanges(t)
	c := control(t)
	var st ipc.StatusResult
	if err := call(t, c, ipc.MethodStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	release := version.Release(st.Version)

	dir := t.TempDir()
	etl := filepath.Join(dir, "s42.etl")
	netsh(t, "trace", "start", "capture=no", "provider=Microsoft-Windows-Kernel-Network", "keywords=0x30", "level=5",
		"tracefile="+etl, "maxsize=512", "overwrite=yes", "report=disabled", "correlation=disabled")
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			netsh(t, "trace", "stop")
		}
	}
	t.Cleanup(stop)

	// a site online through quick share, fetched over the internet
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	const page = "SOIREEHOST-S42-TRAFFIC"
	id := publishTestSite(t, c, page)
	if err := call(t, c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = call(t, c, ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id}, nil) })
	ts := waitTunnel(t, c, 3*time.Minute, "a quick share link", func(ts ipc.TunnelStatus) bool {
		v, ok := quickView(ts, id)
		return ok && v.URL != "" && v.State == ipc.TunnelConnected
	})
	v, _ := quickView(ts, id)
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if code, body, err := fetch(t, v.URL); err == nil && code == 200 && body == page {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the quick share link never served the site")
		}
		time.Sleep(3 * time.Second)
	}
	// the update check: a release build asks GitHub (there is no release
	// manifest yet, so it finds nothing; the connection is what counts)
	if release {
		if err := call(t, c, ipc.MethodUpdateCheck, nil, nil); err != nil {
			t.Fatalf("update.check: %v", err)
		}
		waitUpdateCheck(t, c, 2*time.Minute)
	}
	time.Sleep(10 * time.Second)
	pids := ourProcesses(t)
	stop()

	xmlFile := filepath.Join(dir, "s42.xml")
	//nolint:gosec // G204, G702: a System32 tool with this test's own file names
	out, err := exec.CommandContext(t.Context(), filepath.Join(os.Getenv("SystemRoot"), "System32", "tracerpt.exe"),
		etl, "-o", xmlFile, "-of", "XML", "-y").CombinedOutput()
	if err != nil {
		t.Fatalf("tracerpt: %v\n%s", err, out)
	}
	sends := readSends(t, xmlFile)

	seen := map[string]int{}
	for _, s := range sends {
		role, ours := pids[s.pid]
		if !ours || s.addr.IsLoopback() {
			continue
		}
		seen[role]++
		switch role {
		case winsec.WebService, winsec.TunnelService:
			t.Errorf("%s talked to %s port %d: only loopback is allowed (S-42)", role, s.addr, s.port)
		case tunnel.ExeName:
			if !inRanges(s.addr, cloudflare) && s.port != 53 {
				t.Errorf("cloudflared talked to %s port %d, which is not Cloudflare (S-42)", s.addr, s.port)
			}
		case winsec.SupervisorService:
			if s.port != 53 && (!inRanges(s.addr, github) || s.port != 443) {
				t.Errorf("the supervisor talked to %s port %d, which is not GitHub's HTTPS (S-42)", s.addr, s.port)
			}
		}
	}
	t.Logf("%d sends recorded; outside loopback by role: %v", len(sends), seen)
	// the capture must have seen the traffic it checks, or it proves nothing
	if seen[tunnel.ExeName] == 0 {
		t.Fatal("the trace recorded no cloudflared traffic: the capture did not work")
	}
	if release && seen[winsec.SupervisorService] == 0 {
		t.Fatal("the trace recorded no update check from the supervisor")
	}
}

func netsh(t *testing.T, args ...string) {
	t.Helper()
	//nolint:gosec // G204, G702: a System32 tool with fixed arguments
	out, err := exec.CommandContext(t.Context(), filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("netsh %v: %v\n%s", args, err, out)
	}
}

// waitUpdateCheck waits until the check started by update.check has ended.
func waitUpdateCheck(t *testing.T, c *ipc.Client, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var st ipc.StatusResult
		if err := call(t, c, ipc.MethodStatus, nil, &st); err == nil && !st.Update.LastCheck.IsZero() &&
			st.Update.State != ipc.UpdateChecking && st.Update.State != ipc.UpdateDownloading {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("the update check did not finish")
}

// send is one network event: the process and the far end of the
// conversation. Kernel-Network records sends and receives alike, with
// daddr and saddr from the packet's point of view, so the far end is
// whichever address is not this machine's own.
type send struct {
	pid  uint32
	addr netip.Addr
	port int
}

// readSends reads every Kernel-Network event that names a process and a
// destination (TCP and UDP sends and connects, IPv4 and IPv6) from
// tracerpt's XML.
func readSends(t *testing.T, path string) []send {
	t.Helper()
	local := localAddrs(t)
	f, err := os.Open(path) //nolint:gosec // G304: this test's own trace file
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	type data struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	}
	type event struct {
		Data []data `xml:"EventData>Data"`
	}
	dec := xml.NewDecoder(bufio.NewReader(f))
	var out []send
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading the trace: %v", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev event
		if err := dec.DecodeElement(&ev, &se); err != nil {
			t.Fatalf("reading an event: %v", err)
		}
		fields := map[string]string{}
		for _, d := range ev.Data {
			fields[strings.ToLower(d.Name)] = strings.TrimSpace(d.Value)
		}
		pid, err1 := strconv.ParseUint(fields["pid"], 10, 32)
		daddr, err2 := netip.ParseAddr(fields["daddr"])
		dport, err3 := strconv.Atoi(fields["dport"])
		saddr, err4 := netip.ParseAddr(fields["saddr"])
		sport, err5 := strconv.Atoi(fields["sport"])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			continue
		}
		daddr, saddr = daddr.Unmap(), saddr.Unmap()
		far, port := daddr, dport
		if local[daddr] || daddr.IsLoopback() {
			// a receive (or a local conversation): the sender is the far end
			far, port = saddr, sport
		}
		out = append(out, send{pid: uint32(pid), addr: far, port: port})
	}
	return out
}

// localAddrs are this machine's own addresses.
func localAddrs(t *testing.T) map[netip.Addr]bool {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	out := map[netip.Addr]bool{}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out[p.Addr().Unmap()] = true
		}
	}
	return out
}

// fetchRanges reads CIDR lists, one prefix a line.
func fetchRanges(t *testing.T, urls ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, u := range urls {
		body := getList(t, u)
		for line := range strings.SplitSeq(body, "\n") {
			if p, err := netip.ParsePrefix(strings.TrimSpace(line)); err == nil {
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no ranges from %v", urls)
	}
	return out
}

// githubRanges are the addresses GitHub publishes for its web and API
// hosts, which serve release downloads and the redirects to them.
func githubRanges(t *testing.T) []netip.Prefix {
	t.Helper()
	var meta map[string]any
	if err := json.Unmarshal([]byte(getList(t, "https://api.github.com/meta")), &meta); err != nil {
		t.Fatal(err)
	}
	var out []netip.Prefix
	for _, k := range []string{"web", "api"} {
		list, _ := meta[k].([]any)
		for _, v := range list {
			if s, ok := v.(string); ok {
				if p, err := netip.ParsePrefix(s); err == nil {
					out = append(out, p)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("api.github.com/meta lists no web or API ranges")
	}
	return out
}

func getList(t *testing.T, url string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %v", url, resp.StatusCode, err)
	}
	return string(b)
}

func inRanges(a netip.Addr, ranges []netip.Prefix) bool {
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
