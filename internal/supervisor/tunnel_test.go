package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
)

// report sends a status report from the stand-in tunnel launcher.
func (h *harness) report(r ipc.TunnelReport) {
	h.t.Helper()
	select {
	case h.svc.notify <- ipc.WorkerMsg{Type: ipc.MsgStatus, Report: &r}:
	case <-time.After(10 * time.Second):
		h.t.Fatal("the stand-in launcher could not send its report")
	}
}

func (h *harness) status() ipc.StatusResult {
	h.t.Helper()
	var st ipc.StatusResult
	if err := h.call(ipc.MethodStatus, ipc.None{}, &st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

// S-50: only a Cloudflare Tunnel token is stored.
func TestSecretSetRefusesNonTunnelToken(t *testing.T) {
	h := start(t, nil)
	for _, v := range []string{"1234567890abcdef1234567890abcdef12345", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab", canary, ""} {
		var e *ipc.Error
		err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: v}, nil)
		if !errors.As(err, &e) || e.Code != ipc.CodeInvalid || !strings.Contains(e.Message, "API key") {
			t.Errorf("%q: %v", v, err)
		}
		if v != "" && strings.Contains(fmt.Sprint(err), v) {
			t.Errorf("the error repeats the value")
		}
	}
	var st ipc.SecretStatusResult
	if err := h.call(ipc.MethodSecretStatus, ipc.None{}, &st); err != nil || st.Secrets[0].Set {
		t.Fatalf("something was stored: %+v %v", st, err)
	}
}

// GO-6: two first sets at the same time are serialised, so exactly one
// skips confirmation, and the tunnel ends on the token that was stored.
func TestConcurrentTokenSets(t *testing.T) {
	h := start(t, nil)
	for round := range 5 {
		h.svc.plansMu.Lock()
		h.svc.plans = nil
		h.svc.plansMu.Unlock()
		if round > 0 {
			// start each round with no token stored
			if err := h.sup.secrets.Remove("tunnel_token"); err != nil {
				t.Fatal(err)
			}
		}
		toks := []string{canaryToken(t, 10+2*round), canaryToken(t, 11+2*round)}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				errs[i] = h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: toks[i]}, nil)
			})
		}
		wg.Wait()
		ok := 0
		var won string
		for i, err := range errs {
			var e *ipc.Error
			switch {
			case err == nil:
				ok++
				won = toks[i]
			case errors.As(err, &e) && e.Code == ipc.CodeConfirmationRequired:
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d sets skipped confirmation", round, ok)
		}
		h.waitPlan("the stored token", func(p ipc.TunnelPlan) bool { return p.Token == won })
	}
}

// R-21: whatever the launcher says when it refuses, its words never reach
// the caller, so a token it echoes cannot leak.
func TestTunnelReasonNeverEchoed(t *testing.T) {
	svc := &fakeServices{}
	tok := canaryToken(t, 3)
	svc.tunnelLoad = func(m ipc.WorkerMsg) error {
		if m.Tunnel.Token != "" {
			return errors.New("cloudflared said: bad token " + m.Tunnel.Token)
		}
		return nil
	}
	h := startWith(t, svc, nil, 20*time.Second)
	var st ipc.SecretStatusResult
	if err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: tok}, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], tunnelRefusedReason) {
		t.Fatalf("warnings %q", st.Warnings)
	}
	all := fmt.Sprintf("%+v %+v", st, h.status())
	if strings.Contains(all, canary) || strings.Contains(all, tok) {
		t.Fatalf("the token leaked: %s", all)
	}
}

// ADR-0007: quick share end to end in-process. The share gets ports of its
// own, the launcher is asked for it, and once the launcher reports the
// hostname cloudflared was given, the share's port serves that hostname,
// and only that one (S-06); the link is labelled temporary (S-51).
func TestQuickShareFlow(t *testing.T) {
	h := start(t, nil)
	root := testutil.SiteDir(t)
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("SHARED-PAGE"), 0o600); err != nil {
		t.Fatal(err)
	}
	site := config.Site{ID: "blog", Name: "Blog", Enabled: true, Type: config.TypeStatic, Static: &config.Static{Root: root}}
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: "blog"}, &res); err != nil {
		t.Fatal(err)
	}
	qs := res.Config.Sites[0].QuickShare
	if qs == nil || qs.Port < config.QuickSharePortMin || qs.Port > config.QuickSharePortMax ||
		qs.MetricsPort < config.QuickShareMetricsMin || qs.MetricsPort > config.QuickShareMetricsMax {
		t.Fatalf("quick share %+v", qs)
	}
	plan := h.waitPlan("the share", func(p ipc.TunnelPlan) bool {
		return len(p.Shares) == 1 && p.Shares[0].SiteID == "blog" && p.Shares[0].Port == qs.Port
	})
	if plan.Token != "" || plan.Offline {
		t.Fatalf("plan %v", plan)
	}
	share := fmt.Sprintf("127.0.0.1:%d", qs.Port)
	const host = "seasonal-deck-organisms-sf.trycloudflare.com"
	if code, _ := get(t, share, host, "/"); code != 404 {
		t.Fatalf("before a hostname is known the share answered %d", code)
	}
	h.report(ipc.TunnelReport{Tunnels: []ipc.TunnelState{{Kind: ipc.TunnelKindQuick, SiteID: "blog", State: ipc.TunnelConnected, Connections: 4, Hostname: host}}})
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body := get(t, share, host, "/")
		if code == 200 && body == "SHARED-PAGE" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the share never served its hostname: %d %q", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, other := range []string{"other.trycloudflare.com", "blog.example.com", share} {
		if code, _ := get(t, share, other, "/"); code != 404 {
			t.Errorf("Host %q on the share: %d", other, code)
		}
	}
	st := h.status()
	if len(st.Tunnel.Tunnels) != 1 {
		t.Fatalf("tunnel status %+v", st.Tunnel)
	}
	v := st.Tunnel.Tunnels[0]
	if v.URL != "https://"+host || !v.Temporary || v.Label != ipc.QuickShareLabel || v.State != ipc.TunnelConnected {
		t.Fatalf("view %+v", v)
	}
	// a site.put that omits the share keeps it
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, &res); err != nil || res.Config.Sites[0].QuickShare == nil {
		t.Fatalf("site.put dropped the share: %v", err)
	}
	var stopped ipc.ConfigResult // fresh: decoding keeps a pointer the JSON leaves out
	if err := h.call(ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: "blog"}, &stopped); err != nil {
		t.Fatal(err)
	}
	h.waitPlan("no shares", func(p ipc.TunnelPlan) bool { return len(p.Shares) == 0 })
	if stopped.Config.Sites[0].QuickShare != nil {
		t.Fatal("still shared")
	}
	var page ipc.AuditListResult
	if err := h.call(ipc.MethodAuditList, ipc.AuditListParams{Limit: ipc.MaxAuditPage}, &page); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range page.Entries {
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"quickshare.start", "quickshare.stop"} {
		if !slices.Contains(actions, want) {
			t.Errorf("no %s audit entry in %v", want, actions)
		}
	}
}

func TestQuickShareRefusals(t *testing.T) {
	h := start(t, nil)
	var e *ipc.Error
	if err := h.call(ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: "nope"}, nil); !errors.As(err, &e) || e.Code != ipc.CodeNotFound {
		t.Fatalf("unknown site: %v", err)
	}
	site := h.proxySite("app", fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	site.Enabled = false
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.call(ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: "app"}, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
		t.Fatalf("disabled site: %v", err)
	}
	// R-06: the share's ports never collide with a proxy target
	h.sup.opts.PortFree = func(int) bool { return true }
	site.Enabled = true
	site.Proxy.Target = fmt.Sprintf("127.0.0.1:%d", config.QuickSharePortMin)
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: "app"}, &res); err != nil {
		t.Fatal(err)
	}
	if p := res.Config.Sites[0].QuickShare.Port; p == config.QuickSharePortMin {
		t.Fatalf("share took the proxy target's port %d", p)
	}
}

// The offline switch: no tunnel runs, and it is audited both ways.
func TestOfflineSwitch(t *testing.T) {
	h := start(t, nil)
	if err := h.call(ipc.MethodSecretSet, ipc.SecretSetParams{Name: "tunnel_token", Value: canaryToken(t, 4)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.call(ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: true}, nil); err != nil {
		t.Fatal(err)
	}
	h.waitPlan("offline", func(p ipc.TunnelPlan) bool { return p.Offline })
	if st := h.status(); !st.Tunnel.Offline || !st.Tunnel.TokenSet || st.Tunnel.ServiceURL != "http://"+h.listen {
		t.Fatalf("status %+v", st.Tunnel)
	}
	if err := h.call(ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	h.waitPlan("online", func(p ipc.TunnelPlan) bool { return !p.Offline && p.Token != "" })
}

// S-23: a refused cloudflared shows as Repair needed, in plain words.
func TestRepairNeededInStatus(t *testing.T) {
	h := start(t, nil)
	h.report(ipc.TunnelReport{Tunnels: []ipc.TunnelState{{Kind: ipc.TunnelKindToken, State: ipc.TunnelRefused, Problems: []string{ipc.ProblemBinaryMismatch}}}})
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := h.status()
		if st.Tunnel.RepairNeeded {
			if len(st.Tunnel.Warnings) == 0 || !strings.Contains(st.Tunnel.Warnings[0], "Run Repair") {
				t.Fatalf("warnings %q", st.Tunnel.Warnings)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("repair never reported: %+v", st.Tunnel)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
