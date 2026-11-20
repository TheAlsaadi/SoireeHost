//go:build e2e

package e2e

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// firstSiteLimit is the Phase 6 acceptance check: from the downloaded
// soireehost.exe to the first live site in under 5 minutes.
const firstSiteLimit = 5 * time.Minute

// TestFirstSiteWithinFiveMinutes is the CI stand-in for the Phase 6 check
// "on a fresh Windows 11 virtual machine, going from the downloaded
// soireehost.exe to the first live site takes under 5 minutes" (owner
// decision of 16 Nov 2026: timed on every CI run, and once by hand in a
// VM). The isolation job starts the clock just before setup install, on a
// runner where SoiréeHost was never installed, and passes the start in
// SOIREEHOST_TIMED_START (Unix seconds); this test publishes a folder,
// shares it, and stops the clock when the page loads over the internet.
// The runner is Windows Server 2025, not Windows 11, and nobody clicks:
// the VM check covers the real target and the Windows prompts.
func TestFirstSiteWithinFiveMinutes(t *testing.T) {
	startText := os.Getenv("SOIREEHOST_TIMED_START")
	if startText == "" {
		t.Skip("run by the isolation job's timed first-site step")
	}
	sec, err := strconv.ParseInt(startText, 10, 64)
	if err != nil {
		t.Fatalf("SOIREEHOST_TIMED_START %q: %v", startText, err)
	}
	start := time.Unix(sec, 0)
	waitAllRunning(t)
	c := control(t)
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	const page = "SOIREEHOST-FIRST-SITE"
	id := publishTestSite(t, c, page)
	t.Cleanup(func() { _ = call(t, c, ipc.MethodSiteRemove, ipc.SiteIDParams{ID: id}, nil) })
	if err := call(t, c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = call(t, c, ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id}, nil) })
	ts := waitTunnel(t, c, firstSiteLimit, "a quick share link", func(ts ipc.TunnelStatus) bool {
		v, ok := quickView(ts, id)
		return ok && v.URL != "" && v.State == ipc.TunnelConnected
	})
	v, _ := quickView(ts, id)
	for {
		if code, body, err := fetch(t, v.URL); err == nil && code == 200 && body == page {
			break
		}
		if time.Since(start) > firstSiteLimit {
			t.Fatalf("no live site %s after the download (limit %s)", time.Since(start).Round(time.Second), firstSiteLimit)
		}
		time.Sleep(2 * time.Second)
	}
	took := time.Since(start).Round(time.Second)
	t.Logf("from the downloaded soireehost.exe to a live site: %s (limit %s)", took, firstSiteLimit)
	if took >= firstSiteLimit {
		t.Fatalf("took %s, limit %s", took, firstSiteLimit)
	}
}
