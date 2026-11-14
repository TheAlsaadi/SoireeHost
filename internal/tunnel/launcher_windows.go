package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Options configure a Launcher.
type Options struct {
	// Exe is cloudflared.exe in the install folder; SHA256 its pinned hash.
	Exe    string
	SHA256 string
	// LogDir is the tunnel launcher's own log folder; empty writes no log.
	LogDir string
	// BaseEnv is every cloudflared's environment before the token is added.
	// Nothing else is inherited.
	BaseEnv []string
	// Report receives the launcher's view of every tunnel after each change.
	// Calls come one at a time from a single goroutine.
	Report func(ipc.TunnelReport)
	// Endpoints lists a process's sockets (winsec.EndpointsOf).
	Endpoints func(pid uint32) ([]winsec.Endpoint, error)
	// CheckEvery is how often each cloudflared's sockets are checked.
	CheckEvery time.Duration
	// BackoffMin and BackoffMax bound the restart delay; StableRun is how
	// long a tunnel must stay connected before the delay resets.
	BackoffMin, BackoffMax, StableRun time.Duration
	// Limits are each cloudflared's job limits.
	Limits winsec.Limits
}

// CloudflaredLimits are each cloudflared's job limits (S-21): one process,
// so it can start nothing, and 256 MB.
var CloudflaredLimits = winsec.Limits{MemoryBytes: 256 << 20, ActiveProcesses: 1}

// Launcher runs the cloudflared processes a TunnelPlan asks for.
type Launcher struct {
	opts     Options
	log      *rotatingLog
	ctx      context.Context
	cancel   context.CancelFunc
	reportCh chan struct{}
	applyMu  sync.Mutex

	mu    sync.Mutex
	insts map[string]*instance
}

// spec is one cloudflared process the plan asks for. Any change to it
// restarts that process.
type spec struct {
	kind, siteID, token           string
	port, metricsPort, listenPort int
}

func (s spec) key() string {
	if s.kind == ipc.TunnelKindToken {
		return ipc.TunnelKindToken
	}
	return ipc.TunnelKindQuick + ":" + s.siteID
}

func (s spec) logPrefix() string {
	if s.kind == ipc.TunnelKindToken {
		return "[token]"
	}
	return "[quick " + s.siteID + "]"
}

type instance struct {
	spec   spec
	cancel context.CancelFunc
	done   chan struct{}
	// guarded by Launcher.mu
	st             ipc.TunnelState
	connectedSince time.Time
}

// New starts a launcher with no tunnels.
func New(o Options) (*Launcher, error) {
	if o.Endpoints == nil {
		o.Endpoints = winsec.EndpointsOf
	}
	if o.CheckEvery == 0 {
		o.CheckEvery = 30 * time.Second
	}
	if o.BackoffMin == 0 {
		o.BackoffMin = time.Second
	}
	if o.BackoffMax == 0 {
		o.BackoffMax = time.Minute
	}
	if o.StableRun == 0 {
		o.StableRun = time.Minute
	}
	if o.Limits.ActiveProcesses == 0 {
		o.Limits = CloudflaredLimits
	}
	l := &Launcher{opts: o, reportCh: make(chan struct{}, 1), insts: map[string]*instance{}}
	if o.LogDir != "" {
		log, err := openRotatingLog(o.LogDir, LogMaxBytes)
		if err != nil {
			return nil, fmt.Errorf("opening the tunnel log: %w", err)
		}
		l.log = log
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	go l.reporter()
	return l, nil
}

// Apply makes the running tunnels match the plan: tunnels the plan no longer
// asks for, or asks for differently, are stopped; new ones are started. It
// returns at once; how each tunnel fares arrives through Report.
func (l *Launcher) Apply(p ipc.TunnelPlan) error {
	if err := p.Validate(); err != nil {
		return errors.New("the tunnel plan is not valid")
	}
	if l.ctx.Err() != nil {
		return errors.New("the tunnel launcher is stopping")
	}
	l.applyMu.Lock()
	defer l.applyMu.Unlock()
	desired := map[string]spec{}
	if !p.Offline {
		if p.Token != "" {
			s := spec{kind: ipc.TunnelKindToken, token: p.Token, metricsPort: p.MetricsPort, listenPort: p.ListenPort}
			desired[s.key()] = s
		}
		for _, sh := range p.Shares {
			s := spec{kind: ipc.TunnelKindQuick, siteID: sh.SiteID, port: sh.Port, metricsPort: sh.MetricsPort, listenPort: p.ListenPort}
			desired[s.key()] = s
		}
	}
	l.mu.Lock()
	var stop []*instance
	for k, in := range l.insts {
		if d, ok := desired[k]; !ok || d != in.spec {
			stop = append(stop, in)
			delete(l.insts, k)
		}
	}
	l.mu.Unlock()
	for _, in := range stop {
		in.cancel()
		<-in.done
	}
	l.mu.Lock()
	for k, d := range desired {
		if _, ok := l.insts[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(l.ctx)
		in := &instance{spec: d, cancel: cancel, done: make(chan struct{}),
			st: ipc.TunnelState{Kind: d.kind, SiteID: d.siteID, State: ipc.TunnelStarting, Since: time.Now().UTC()}}
		l.insts[k] = in
		go l.run(ctx, in)
	}
	l.mu.Unlock()
	l.kick()
	return nil
}

// Close stops every tunnel and waits for their processes to end.
func (l *Launcher) Close() {
	l.applyMu.Lock()
	defer l.applyMu.Unlock()
	l.cancel()
	l.mu.Lock()
	all := make([]*instance, 0, len(l.insts))
	for k, in := range l.insts {
		all = append(all, in)
		delete(l.insts, k)
	}
	l.mu.Unlock()
	for _, in := range all {
		<-in.done
	}
	_ = l.log.Close()
}

// Snapshot is the launcher's view of every tunnel: the token tunnel first,
// then quick shares by site.
func (l *Launcher) Snapshot() ipc.TunnelReport {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := ipc.TunnelReport{Tunnels: []ipc.TunnelState{}}
	for _, in := range l.insts {
		st := in.st
		st.Problems = slices.Clone(st.Problems)
		r.Tunnels = append(r.Tunnels, st)
	}
	slices.SortFunc(r.Tunnels, func(a, b ipc.TunnelState) int {
		if a.Kind != b.Kind {
			if a.Kind == ipc.TunnelKindToken {
				return -1
			}
			return 1
		}
		if a.SiteID < b.SiteID {
			return -1
		}
		if a.SiteID > b.SiteID {
			return 1
		}
		return 0
	})
	return r
}

func (l *Launcher) kick() {
	select {
	case l.reportCh <- struct{}{}:
	default:
	}
}

func (l *Launcher) reporter() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-l.reportCh:
			if l.opts.Report != nil {
				l.opts.Report(l.Snapshot())
			}
		}
	}
}

// update changes an instance's state, if it is still current, and reports.
func (l *Launcher) update(in *instance, f func(st *ipc.TunnelState, in *instance)) {
	l.mu.Lock()
	before := in.st.State
	f(&in.st, in)
	if in.st.State != before {
		in.st.Since = time.Now().UTC()
	}
	l.mu.Unlock()
	l.kick()
}

// run keeps one cloudflared going until ctx ends, restarting it with
// backoff.
func (l *Launcher) run(ctx context.Context, in *instance) {
	defer close(in.done)
	backoff := l.opts.BackoffMin
	for ctx.Err() == nil {
		l.update(in, func(st *ipc.TunnelState, in *instance) {
			st.State, st.Connections, st.Hostname, st.Problems = ipc.TunnelStarting, 0, "", nil
			in.connectedSince = time.Time{}
		})
		problem := l.runOnce(ctx, in)
		if ctx.Err() != nil {
			return
		}
		var stable bool
		l.update(in, func(st *ipc.TunnelState, in *instance) {
			st.State, st.Connections, st.Hostname = ipc.TunnelDown, 0, ""
			switch problem {
			case ipc.ProblemBinaryMissing, ipc.ProblemBinaryMismatch, ipc.ProblemUnexpectedListener:
				st.State = ipc.TunnelRefused
			}
			st.Problems = []string{problem}
			stable = !in.connectedSince.IsZero() && time.Since(in.connectedSince) >= l.opts.StableRun
			in.connectedSince = time.Time{}
		})
		if stable {
			backoff = l.opts.BackoffMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, l.opts.BackoffMax)
	}
}

// runOnce starts cloudflared once and returns the problem that ended it.
func (l *Launcher) runOnce(ctx context.Context, in *instance) string {
	img, problem := openVerified(l.opts.Exe, l.opts.SHA256)
	if problem != "" {
		return problem
	}
	proc, err := winsec.StartConfined(winsec.ProcessSpec{
		Path:   l.opts.Exe,
		Args:   cloudflaredArgs(in.spec),
		Env:    l.env(in.spec),
		Dir:    filepath.Dir(l.opts.Exe),
		Limits: l.opts.Limits,
	})
	// The handle is held, with no write or delete sharing, until the
	// process exists: the file that was hashed is the file that runs. Once
	// it runs, Windows keeps its image from being changed.
	_ = img.Close()
	if err != nil {
		l.log.writeLine(in.spec.logPrefix(), []byte("SoiréeHost: cloudflared could not be started: "+err.Error()))
		return ipc.ProblemStartFailed
	}
	defer proc.Close() //nolint:errcheck // ends the process if it is still running

	sc := newScrubber(in.spec.token)
	out := newOutputState(in.spec.kind == ipc.TunnelKindQuick, in.spec.listenPort)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_ = readLines(proc.Output, func(line []byte) {
			clean := sc.scrub(line)
			l.log.writeLine(in.spec.logPrefix(), clean)
			if !out.feed(clean) {
				return
			}
			l.update(in, func(st *ipc.TunnelState, in *instance) {
				st.Connections, st.Hostname = out.connections(), out.hostname
				switch {
				case st.Connections > 0:
					st.State = ipc.TunnelConnected
					if in.connectedSince.IsZero() {
						in.connectedSince = time.Now()
					}
				case out.everConnected:
					st.State = ipc.TunnelReconnecting
				default:
					st.State = ipc.TunnelStarting
				}
				st.Problems = nil
				if out.ingressOutside {
					st.Problems = []string{ipc.ProblemIngressOutside}
				}
			})
		})
	}()
	exited := make(chan struct{})
	go func() {
		_, _ = proc.Wait()
		close(exited)
	}()
	end := func(problem string) string {
		_ = proc.Kill()
		<-exited
		<-readDone
		return problem
	}
	// first socket check soon after start, then every CheckEvery
	check := time.NewTimer(min(time.Second, l.opts.CheckEvery))
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return end("")
		case <-exited:
			<-readDone
			return ipc.ProblemExited
		case <-check.C:
			if !l.listenersOK(proc.Pid) {
				l.log.writeLine(in.spec.logPrefix(), []byte("SoiréeHost: cloudflared listened on an address other than loopback, or used UDP; it was stopped (S-01)"))
				return end(ipc.ProblemUnexpectedListener)
			}
			check.Reset(l.opts.CheckEvery)
		}
	}
}

// listenersOK checks a cloudflared's sockets: TCP listeners on 127.0.0.1 or
// ::1 only, and no UDP socket at all (it runs with --protocol http2). A
// failure to list them counts as not OK (fail closed).
func (l *Launcher) listenersOK(pid uint32) bool {
	eps, err := l.opts.Endpoints(pid)
	if err != nil {
		return false
	}
	for _, ep := range eps {
		if ep.Proto != "tcp" {
			return false
		}
	}
	return winsec.CheckLoopbackOnly(eps) == nil
}

// cloudflaredArgs are fixed except for ports, which are numbers (ADR-0007
// section 2). The token is never among them (S-23).
func cloudflaredArgs(s spec) []string {
	args := []string{
		"tunnel",
		"--no-autoupdate",
		"--protocol", "http2",
		"--metrics", "127.0.0.1:" + strconv.Itoa(s.metricsPort),
		"--management-diagnostics=false",
		"--output", "json",
		"--loglevel", "info",
	}
	if s.kind == ipc.TunnelKindToken {
		return append(args, "run")
	}
	return append(args, "--url", "http://127.0.0.1:"+strconv.Itoa(s.port))
}

// env is BaseEnv plus, for the token tunnel, TUNNEL_TOKEN: the token reaches
// cloudflared only through its environment, which only its own account and
// administrators can read (S-23).
func (l *Launcher) env(s spec) []string {
	env := slices.Clone(l.opts.BaseEnv)
	if s.kind == ipc.TunnelKindToken {
		env = append(env, "TUNNEL_TOKEN="+s.token)
	}
	return env
}

// ServiceEnv is the environment cloudflared gets from a service: the few
// variables Windows programs need, taken from the tunnel launcher's own
// (its service profile), and nothing else.
func ServiceEnv() []string {
	var env []string
	for _, k := range []string{"SystemRoot", "windir", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// openVerified opens cloudflared with read sharing only, so it cannot be
// written, renamed or deleted while the handle is open, and checks its
// SHA-256 through that handle (S-23). The caller starts the same path while
// it still holds the handle.
func openVerified(path, want string) (*os.File, string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ipc.ProblemBinaryMissing
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, ipc.ProblemBinaryMissing
	}
	if err != nil {
		return nil, ipc.ProblemStartFailed
	}
	f := os.NewFile(uintptr(h), path)
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		_ = f.Close()
		return nil, ipc.ProblemStartFailed
	}
	if hex.EncodeToString(sum.Sum(nil)) != want {
		_ = f.Close()
		return nil, ipc.ProblemBinaryMismatch
	}
	return f, ""
}

// InstalledExe is cloudflared's path next to the running soireehost.exe.
func InstalledExe() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(self), ExeName), nil
}
