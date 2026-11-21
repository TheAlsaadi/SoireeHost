//go:build e2e

package e2e

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/tunnel"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// The soak (plan section 10: 72 hours of serving with tunnel drops and
// restarts injected; watch memory and handle counts). The owner runs it in
// the VirtualBox VM on the release candidate (owner decision, 21 Nov 2026):
//
//	SOIREEHOST_E2E=1 SOIREEHOST_SOAK_HOURS=72 SOIREEHOST_SOAK_DIR=C:\soak
//	e2e.test.exe -test.run=^TestSoak$ -test.v -test.timeout=0
//
// It shares one site through quick share and fetches it over the internet
// every probe; every few hours it drops the tunnel (kills cloudflared) and
// every day it restarts the supervisor, which restarts everything. It writes
// probes.csv, samples.csv and faults.csv to the soak folder, and fails if
// the site is down outside a fault's recovery window, does not come back
// after a fault, or a process's memory or handles keep growing.
const (
	soakProbeEvery   = 30 * time.Second
	soakSampleEvery  = 5 * time.Minute
	soakDropEvery    = 4 * time.Hour
	soakRestartEvery = 24 * time.Hour
	// soakRecovery is how long the site may be down after a fault: a new
	// quick share link needs cloudflared to start and register it
	soakRecovery = 10 * time.Minute
	// soakMinUp is the share of probes outside recovery windows that must
	// succeed; trycloudflare itself drops the odd request
	soakMinUp = 0.99
	// a process "keeps growing" when its last hour is above its first hour
	// after warm-up by more than both the factor and the absolute amount
	soakWarmup        = time.Hour
	soakGrowthFactor  = 1.5
	soakGrowthBytes   = 64 << 20
	soakGrowthHandles = 500
	// cloudflared lives 4 hours between drops; 3 hours leaves a warm-up hour,
	// a first hour and a last hour to compare
	soakMinLife = 3 * time.Hour
	soakPage    = "SOIREEHOST-SOAK"
)

var procGetProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")

type soakSample struct {
	at      time.Time
	pid     uint32
	role    string
	private uint64
	handles uint32
}

type soakFault struct {
	at   time.Time
	kind string
}

func TestSoak(t *testing.T) {
	hoursText := os.Getenv("SOIREEHOST_SOAK_HOURS")
	if hoursText == "" {
		t.Skip("set SOIREEHOST_SOAK_HOURS to run the soak (in the owner's VM)")
	}
	hours, err := strconv.ParseFloat(hoursText, 64)
	if err != nil || hours <= 0 || hours > 24*14 {
		t.Fatalf("SOIREEHOST_SOAK_HOURS %q: a number of hours up to two weeks", hoursText)
	}
	dir := os.Getenv("SOIREEHOST_SOAK_DIR")
	if dir == "" {
		t.Fatal("set SOIREEHOST_SOAK_DIR to a folder outside your user profile, for example C:\\soak")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the soak's own output folder
		t.Fatal(err)
	}
	waitAllRunning(t)
	c := control(t)
	if err := call(t, c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: false}, nil); err != nil {
		t.Fatal(err)
	}
	id := publishTestSite(t, c, soakPage)
	t.Cleanup(func() {
		if c2, err := dialSoak(context.Background()); err == nil {
			_ = c2.Call(context.Background(), ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id}, nil)
			_ = c2.Call(context.Background(), ipc.MethodSiteRemove, ipc.SiteIDParams{ID: id}, nil)
			_ = c2.Close()
		}
	})
	if err := call(t, c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id}, nil); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	probes := soakCSV(t, dir, "probes.csv", "time", "url", "status", "ms", "error")
	samples := soakCSV(t, dir, "samples.csv", "time", "pid", "role", "private_bytes", "handles")
	faults := soakCSV(t, dir, "faults.csv", "time", "kind", "error")

	start := time.Now()
	end := start.Add(time.Duration(hours * float64(time.Hour)))
	// a short trial run (under a day) still drops the tunnel and restarts
	// the supervisor, at a quarter and a half of its length
	dropEvery, restartEvery := soakDropEvery, soakRestartEvery
	if total := end.Sub(start); total < soakRestartEvery {
		dropEvery, restartEvery = total/4, total/2
	}
	nextSample, nextDrop, nextRestart := start, start.Add(dropEvery), start.Add(restartEvery)
	var (
		ups, downs int
		lastFault  time.Time
		pending    []soakFault // faults whose site has not come back yet
		failures   []string
		all        []soakSample
	)
	t.Logf("soak: %.1f hours, writing to %s", hours, dir)
	for now := time.Now(); now.Before(end); now = time.Now() {
		if !now.Before(nextSample) {
			for _, s := range soakSampleProcesses() {
				all = append(all, s)
				soakRow(samples, s.at.Format(time.RFC3339), fmt.Sprint(s.pid), s.role, fmt.Sprint(s.private), fmt.Sprint(s.handles))
			}
			nextSample = now.Add(soakSampleEvery)
		}
		switch {
		case !now.Before(nextRestart):
			err := soakRestartSupervisor()
			soakRow(faults, now.Format(time.RFC3339), "restart-supervisor", soakErr(err))
			pending, lastFault = append(pending, soakFault{now, "restart-supervisor"}), now
			nextRestart, nextDrop = now.Add(restartEvery), now.Add(dropEvery)
		case !now.Before(nextDrop):
			err := soakKillCloudflared()
			soakRow(faults, now.Format(time.RFC3339), "drop-tunnel", soakErr(err))
			pending, lastFault = append(pending, soakFault{now, "drop-tunnel"}), now
			nextDrop = now.Add(dropEvery)
		}

		url, code, ms, perr := soakProbe(t, id)
		soakRow(probes, now.Format(time.RFC3339), url, fmt.Sprint(code), fmt.Sprint(ms), soakErr(perr))
		ok := perr == nil && code == 200
		switch {
		case ok:
			ups++
			pending = pending[:0]
		case lastFault.IsZero() || now.Sub(lastFault) > soakRecovery:
			downs++
		}
		for _, f := range pending {
			if now.Sub(f.at) > soakRecovery {
				failures = append(failures, fmt.Sprintf("the site did not come back within %s after %s at %s", soakRecovery, f.kind, f.at.Format(time.RFC3339)))
			}
		}
		pending = slices.DeleteFunc(pending, func(f soakFault) bool { return now.Sub(f.at) > soakRecovery })
		time.Sleep(soakProbeEvery)
	}

	if total := ups + downs; total == 0 {
		failures = append(failures, "no probe counted")
	} else if up := float64(ups) / float64(total); up < soakMinUp {
		failures = append(failures, fmt.Sprintf("the site answered %.2f%% of probes outside recovery windows, below %.0f%%", up*100, soakMinUp*100))
	} else {
		t.Logf("availability outside recovery windows: %.3f%% of %d probes", up*100, total)
	}
	failures = append(failures, soakGrowth(t, all)...)
	for _, f := range failures {
		t.Error(f)
	}
}

// dialSoak opens the control pipe without failing the test: the supervisor
// is briefly away during a restart.
func dialSoak(ctx context.Context) (*ipc.Client, error) {
	l, err := setup.DefaultLayout()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return ipc.DialControlFile(ctx, ipc.PipeFilePath(l.DataRoot, ipc.ControlPipeFile), winsec.ServiceSID(winsec.SupervisorService))
}

// soakProbe finds the share's current link and fetches the page through it.
func soakProbe(t *testing.T, id string) (string, int, int64, error) {
	c, err := dialSoak(t.Context())
	if err != nil {
		return "", 0, 0, fmt.Errorf("control pipe: %w", err)
	}
	var st ipc.StatusResult
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	err = c.Call(ctx, ipc.MethodStatus, ipc.None{}, &st)
	cancel()
	_ = c.Close()
	if err != nil {
		return "", 0, 0, fmt.Errorf("status: %w", err)
	}
	v, ok := quickView(st.Tunnel, id)
	if !ok || v.URL == "" {
		return "", 0, 0, fmt.Errorf("no quick share link yet (state %q)", v.State)
	}
	began := time.Now()
	code, body, err := fetch(t, v.URL)
	ms := time.Since(began).Milliseconds()
	if err == nil && code == 200 && body != soakPage {
		err = fmt.Errorf("unexpected page (%d bytes)", len(body))
	}
	return v.URL, code, ms, err
}

// soakSampleProcesses reads each SoiréeHost and cloudflared process's
// private bytes and handle count. A process that ends meanwhile is skipped.
func soakSampleProcesses() []soakSample {
	pids := map[uint32]string{}
	if m, err := mgr.Connect(); err == nil {
		for _, n := range []string{winsec.SupervisorService, winsec.WebService, winsec.TunnelService} {
			if s, err := m.OpenService(n); err == nil {
				if st, err := s.Query(); err == nil && st.ProcessId != 0 {
					pids[st.ProcessId] = n
				}
				_ = s.Close()
			}
		}
		_ = m.Disconnect()
	}
	if snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); err == nil {
		var pe windows.ProcessEntry32
		pe.Size = uint32(unsafe.Sizeof(pe))
		for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
			if windows.UTF16ToString(pe.ExeFile[:]) == tunnel.ExeName {
				pids[pe.ProcessID] = tunnel.ExeName
			}
		}
		_ = windows.CloseHandle(snap)
	}
	now := time.Now()
	var out []soakSample
	for pid, role := range pids {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		var mc processMemoryCounters
		mc.cb = uint32(unsafe.Sizeof(mc))
		r1, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mc)), uintptr(mc.cb)) //nolint:gosec // G103: Windows API arguments
		var handles uint32
		r2, _, _ := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&handles))) //nolint:gosec // G103: Windows API arguments
		_ = windows.CloseHandle(h)
		if r1 == 0 || r2 == 0 {
			continue
		}
		out = append(out, soakSample{at: now, pid: pid, role: role, private: uint64(mc.PagefileUsage), handles: handles})
	}
	return out
}

// soakKillCloudflared drops the tunnel: the launcher sees cloudflared end
// and starts it again, and quick share gets a new link.
func soakKillCloudflared() error {
	var errs []error
	killed := 0
	for _, s := range soakSampleProcesses() {
		if s.role != tunnel.ExeName {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, s.pid)
		if err == nil {
			err = windows.TerminateProcess(h, 1)
			_ = windows.CloseHandle(h)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		killed++
	}
	if killed == 0 {
		return fmt.Errorf("no cloudflared process killed (%v)", errs)
	}
	return nil
}

// soakRestartSupervisor stops the supervisor, which stops both workers,
// and starts it again.
func soakRestartSupervisor() error {
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
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	for deadline := time.Now().Add(2 * time.Minute); ; {
		st, err := s.Query()
		if err == nil && st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("supervisor did not stop within 2 minutes")
		}
		time.Sleep(time.Second)
	}
	return s.Start()
}

// soakGrowth reports a process whose memory or handles kept growing: for
// every process that lived at least soakMinLife, its first hour after
// warm-up against its last hour (medians). Restarts start a new process,
// so only growth within one process's life counts.
func soakGrowth(t *testing.T, all []soakSample) []string {
	byPID := map[uint32][]soakSample{}
	for _, s := range all {
		byPID[s.pid] = append(byPID[s.pid], s)
	}
	var out []string
	for pid, ss := range byPID {
		first, last := ss[0].at, ss[len(ss)-1].at
		if last.Sub(first) < soakMinLife {
			continue
		}
		var early, late []soakSample
		for _, s := range ss {
			switch {
			case s.at.After(first.Add(soakWarmup)) && !s.at.After(first.Add(2*soakWarmup)):
				early = append(early, s)
			case s.at.After(last.Add(-time.Hour)):
				late = append(late, s)
			}
		}
		if len(early) == 0 || len(late) == 0 {
			continue
		}
		role := ss[0].role
		e, l := medianOf(early, func(s soakSample) uint64 { return s.private }), medianOf(late, func(s soakSample) uint64 { return s.private })
		eh, lh := medianOf(early, func(s soakSample) uint64 { return uint64(s.handles) }), medianOf(late, func(s soakSample) uint64 { return uint64(s.handles) })
		t.Logf("%s (pid %d, %s): private %d -> %d MB, handles %d -> %d", role, pid, last.Sub(first).Round(time.Minute), e>>20, l>>20, eh, lh)
		if float64(l) > float64(e)*soakGrowthFactor && l-e > soakGrowthBytes {
			out = append(out, fmt.Sprintf("%s (pid %d): private memory grew from %d MB to %d MB", role, pid, e>>20, l>>20))
		}
		if float64(lh) > float64(eh)*soakGrowthFactor && lh-eh > soakGrowthHandles {
			out = append(out, fmt.Sprintf("%s (pid %d): handles grew from %d to %d", role, pid, eh, lh))
		}
	}
	return out
}

func medianOf(ss []soakSample, f func(soakSample) uint64) uint64 {
	v := make([]uint64, len(ss))
	for i, s := range ss {
		v[i] = f(s)
	}
	slices.Sort(v)
	return v[len(v)/2]
}

func soakCSV(t *testing.T, dir, name string, header ...string) *csv.Writer {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name)) //nolint:gosec // G304: the soak's own output folder
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	w := csv.NewWriter(f)
	soakRow(w, header...)
	return w
}

// soakRow writes and flushes one row, so a soak stopped early keeps its data.
func soakRow(w *csv.Writer, fields ...string) {
	_ = w.Write(fields)
	w.Flush()
}

func soakErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
