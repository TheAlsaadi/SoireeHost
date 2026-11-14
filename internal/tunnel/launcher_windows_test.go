package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// fakeEnv names the mode in which this test binary plays cloudflared.
const fakeEnv = "SOIREEHOST_FAKE_CLOUDFLARED"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeEnv); mode != "" {
		os.Exit(fakeCloudflared(mode))
	}
	os.Exit(m.Run())
}

// fakeCloudflared writes what cloudflared 2026.11.0 writes with --output
// json, in the given mode, then waits to be killed.
func fakeCloudflared(mode string) int {
	say := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	args := strings.Join(os.Args[1:], " ")
	for _, want := range []string{"tunnel", "--no-autoupdate", "--protocol http2", "--metrics 127.0.0.1:", "--management-diagnostics=false", "--output json", "--loglevel info"} {
		if !strings.Contains(args, want) {
			say(`{"level":"error","message":"BAD-ARGS missing %s"}`, want)
		}
	}
	say(`{"level":"info","message":"ARGS %s"}`, strings.ReplaceAll(args, `"`, `'`))
	tok, hasTok := os.LookupEnv("TUNNEL_TOKEN")
	_, hasPath := os.LookupEnv("PATH")
	say(`{"level":"info","message":"TOKEN-PRESENT=%v PATH-PRESENT=%v"}`, hasTok, hasPath)
	switch mode {
	case "quick":
		host := os.Getenv("FAKE_HOST")
		say(`%s`, lineRequest)
		say(`%s`, lineBorder)
		say(`%s`, lineCreated)
		say(`{"level":"info","message":"|  https://%s                                      |"}`, host)
		for i := range 4 {
			say(`%s`, registered(i))
		}
	case "token":
		// cloudflared echoing the token must never reach a log (R-21)
		say(`{"level":"error","message":"failed to parse token %s"}`, tok)
		for i := range 4 {
			say(`%s`, registered(i))
		}
		say(`{"level":"info","version":1,"config":"{\"ingress\":[{\"service\":\"http://192.168.1.5:80\"}],\"warp-routing\":{\"enabled\":false}}","message":"Updated to new configuration"}`)
	case "exit":
		say(`%s`, registered(0))
		return 3
	case "udp":
		pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err != nil {
			say(`{"level":"error","message":"no udp: %v"}`, err)
			return 1
		}
		defer pc.Close() //nolint:errcheck // process ends here
		say(`%s`, registered(0))
	}
	time.Sleep(10 * time.Minute)
	return 0
}

func selfHash(t *testing.T) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe) //nolint:gosec // G304: this test binary
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return exe, hex.EncodeToString(h.Sum(nil))
}

type harness struct {
	l       *Launcher
	reports chan ipc.TunnelReport
	logDir  string
}

func start(t *testing.T, mode string, mutate func(*Options)) *harness {
	t.Helper()
	exe, sum := selfHash(t)
	h := &harness{reports: make(chan ipc.TunnelReport, 256), logDir: t.TempDir()}
	o := Options{
		Exe: exe, SHA256: sum, LogDir: h.logDir,
		BaseEnv:    []string{"SystemRoot=" + os.Getenv("SystemRoot"), fakeEnv + "=" + mode, "FAKE_HOST=fake-share-one.trycloudflare.com"},
		CheckEvery: 200 * time.Millisecond,
		BackoffMin: 50 * time.Millisecond, BackoffMax: 200 * time.Millisecond,
		Report: func(r ipc.TunnelReport) { h.reports <- r },
	}
	if mutate != nil {
		mutate(&o)
	}
	l, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	h.l = l
	t.Cleanup(l.Close)
	return h
}

// wait returns the first report for which ok is true.
func (h *harness) wait(t *testing.T, what string, ok func(ipc.TunnelReport) bool) ipc.TunnelReport {
	t.Helper()
	deadline := time.After(30 * time.Second)
	var last ipc.TunnelReport
	for {
		select {
		case r := <-h.reports:
			if err := r.Validate(); err != nil {
				t.Fatalf("invalid report %+v: %v", r, err)
			}
			last = r
			if ok(r) {
				return r
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s; last report %+v", what, last)
		}
	}
}

func (h *harness) logText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.logDir, LogName))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func one(r ipc.TunnelReport) (ipc.TunnelState, bool) {
	if len(r.Tunnels) != 1 {
		return ipc.TunnelState{}, false
	}
	return r.Tunnels[0], true
}

func plan(t *testing.T) ipc.TunnelPlan {
	return ipc.TunnelPlan{ListenPort: 8787, MetricsPort: 20241}
}

// TestLauncherQuickShare: a quick share reports its hostname, taken from
// cloudflared's own output, and its connections; going offline stops it.
func TestLauncherQuickShare(t *testing.T) {
	h := start(t, "quick", nil)
	p := plan(t)
	p.Shares = []ipc.SharePlan{{SiteID: "blog", Port: 8788, MetricsPort: 20242}}
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "a connected quick share", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.Kind == ipc.TunnelKindQuick && st.SiteID == "blog" && st.State == ipc.TunnelConnected &&
			st.Connections == 4 && st.Hostname == "fake-share-one.trycloudflare.com"
	})
	log := h.logText(t)
	if strings.Contains(log, "BAD-ARGS") || !strings.Contains(log, "--url http://127.0.0.1:8788") || !strings.Contains(log, "--metrics 127.0.0.1:20242") {
		t.Fatalf("cloudflared got the wrong arguments:\n%s", log)
	}
	if !strings.Contains(log, "TOKEN-PRESENT=false PATH-PRESENT=false") {
		t.Fatalf("a quick share saw a token or an inherited environment:\n%s", log)
	}
	p.Offline = true
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "no tunnels while offline", func(r ipc.TunnelReport) bool { return len(r.Tunnels) == 0 })
}

// TestLauncherTokenNeverLeaks (S-23, R-21): the token reaches cloudflared in
// its environment only; it is not on its command line, and a line in which
// cloudflared repeats it is scrubbed before it reaches the log.
func TestLauncherTokenNeverLeaks(t *testing.T) {
	h := start(t, "token", nil)
	p := plan(t)
	p.Token = testToken(t)
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	r := h.wait(t, "a connected token tunnel with an ingress warning", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelConnected && slices.Contains(st.Problems, ipc.ProblemIngressOutside)
	})
	if st, _ := one(r); st.Kind != ipc.TunnelKindToken || st.Hostname != "" {
		t.Fatalf("state %+v", st)
	}
	log := h.logText(t)
	if !strings.Contains(log, "TOKEN-PRESENT=true") {
		t.Fatalf("cloudflared did not get its token:\n%s", log)
	}
	for _, leak := range []string{p.Token, "CANARY-TUNNEL-SECRET", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(log, leak) {
			t.Fatalf("the log holds a secret part %q", leak)
		}
	}
	if !strings.Contains(log, "failed to parse token "+redacted) {
		t.Fatalf("the echoed token was not replaced:\n%s", log)
	}
}

// TestLauncherRefusesTamperedBinary (S-23): a cloudflared whose hash does
// not match the pin never runs, and the tunnel reports Repair needed.
func TestLauncherRefusesTamperedBinary(t *testing.T) {
	h := start(t, "quick", func(o *Options) { o.SHA256 = strings.Repeat("0", 64) })
	p := plan(t)
	p.Token = testToken(t)
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "refused", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelRefused && slices.Equal(st.Problems, []string{ipc.ProblemBinaryMismatch})
	})
	if strings.Contains(h.logText(t), "ARGS") {
		t.Fatal("the tampered binary ran")
	}
}

func TestLauncherMissingBinary(t *testing.T) {
	h := start(t, "quick", func(o *Options) { o.Exe = filepath.Join(t.TempDir(), ExeName) })
	p := plan(t)
	p.Shares = []ipc.SharePlan{{SiteID: "blog", Port: 8788, MetricsPort: 20242}}
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "refused", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelRefused && slices.Equal(st.Problems, []string{ipc.ProblemBinaryMissing})
	})
}

// TestLauncherRestartsAfterExit: a cloudflared that exits is restarted.
func TestLauncherRestartsAfterExit(t *testing.T) {
	h := start(t, "exit", nil)
	p := plan(t)
	p.Shares = []ipc.SharePlan{{SiteID: "blog", Port: 8788, MetricsPort: 20242}}
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "down after an exit", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelDown && slices.Equal(st.Problems, []string{ipc.ProblemExited})
	})
	h.wait(t, "started again", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelConnected
	})
}

// TestLauncherStopsUDP (S-01): a cloudflared with a UDP socket is stopped.
func TestLauncherStopsUDP(t *testing.T) {
	h := start(t, "udp", nil)
	p := plan(t)
	p.Shares = []ipc.SharePlan{{SiteID: "blog", Port: 8788, MetricsPort: 20242}}
	if err := h.l.Apply(p); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "refused for a listener", func(r ipc.TunnelReport) bool {
		st, ok := one(r)
		return ok && st.State == ipc.TunnelRefused && slices.Equal(st.Problems, []string{ipc.ProblemUnexpectedListener})
	})
}

func TestApplyRefusesBadPlan(t *testing.T) {
	h := start(t, "quick", nil)
	if err := h.l.Apply(ipc.TunnelPlan{Token: "not a token", ListenPort: 8787, MetricsPort: 20241}); err == nil {
		t.Fatal("bad plan accepted")
	}
}
