package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Worker states as status.get reports them.
const (
	StateStarting = "starting"
	StateRunning  = "running"
	StateDown     = "down"
	StateStopped  = "stopped"
)

// errWorkerDown means the worker is not connected; a saved change applies
// when it next connects.
var errWorkerDown = errors.New("worker is not running")

// stableRun is how long a worker must stay connected before its restart
// delay goes back to one second (ADR-0006: 1, 2, 4 ... 60 s). Resetting on
// hello let a worker that connects and then dies restart every second for
// ever (review finding R-24).
const stableRun = time.Minute

// stopSendTimeout bounds the wait to hand a worker its stop message.
const stopSendTimeout = 2 * time.Second

// loadError means a load did not take effect: the worker refused it
// (refused), or it went away or did not answer in time while loading. A
// change that ends in any of these is undone (S-41, review finding R-22);
// at reconnect only a refusal makes the supervisor roll back.
type loadError struct {
	reason  string
	refused bool
}

func (e *loadError) Error() string { return e.reason }

// workerMgr starts one worker service, waits for it on its pipe, feeds it
// loads and restarts it when it goes away.
type workerMgr struct {
	sup     *Supervisor
	role    string
	service string
	sid     string

	mu       sync.Mutex
	conn     *ipc.WorkerConn
	state    string
	since    time.Time
	lastErr  string
	restarts int
	pending  map[uint64]chan error
	nextLoad uint64
}

func newWorkerMgr(s *Supervisor, role, service, sid string) *workerMgr {
	return &workerMgr{sup: s, role: role, service: service, sid: sid, state: StateStopped, since: time.Now(), pending: map[uint64]chan error{}}
}

func (w *workerMgr) setState(state, lastErr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state, w.since = state, time.Now()
	if lastErr != "" {
		w.lastErr = lastErr
	}
}

func (w *workerMgr) status() ipc.WorkerStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return ipc.WorkerStatus{Role: w.role, State: w.state, Since: w.since, LastError: w.lastErr, Restarts: w.restarts}
}

// run keeps the worker going until ctx ends, then stops it.
func (w *workerMgr) run(ctx context.Context, ln net.Listener) {
	accepted := make(chan net.Conn)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			select {
			case accepted <- c:
			case <-ctx.Done():
				_ = c.Close()
			}
		}
	}()
	defer func() {
		_ = ln.Close()
		w.stop()
		w.setState(StateStopped, "")
	}()

	backoff := time.Second
	for ctx.Err() == nil {
		w.setState(StateStarting, "")
		if err := w.sup.opts.Services.Start(w.service); err != nil {
			w.setState(StateDown, "could not start the service: "+err.Error())
		} else if c, ok := w.await(ctx, accepted); ok {
			began := time.Now()
			w.serve(ctx, c)
			if time.Since(began) >= stableRun {
				backoff = time.Second
			}
		}
		if ctx.Err() != nil {
			return
		}
		w.mu.Lock()
		w.restarts++
		n := w.restarts
		w.mu.Unlock()
		// Restarts go to the audit log (the supervisor cannot write the
		// worker's own log folder). The worker's reason is left out: it is
		// the worker's text, and the tunnel's could echo its token (R-21).
		// Once the delay is at its cap, only every 60th restart (about one
		// an hour) is recorded, so a worker that can never start does not
		// grow the audit log without bound; the count shows the gap.
		if backoff < time.Minute || n%60 == 0 {
			w.sup.record(winsec.SIDSystem, "worker.restart", map[string]string{
				"role": w.role, "restarts": strconv.Itoa(n), "delay": backoff.String()})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// await waits for the started worker to connect and say hello, and checks
// that the client is the worker's own service account.
func (w *workerMgr) await(ctx context.Context, accepted <-chan net.Conn) (*ipc.WorkerConn, bool) {
	timer := time.NewTimer(w.sup.opts.WorkerStartTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false
	case <-timer.C:
		w.setState(StateDown, "the worker did not connect in time")
		return nil, false
	case c, ok := <-accepted:
		if !ok {
			return nil, false
		}
		wc := ipc.NewWorkerConn(c)
		_ = c.SetReadDeadline(time.Now().Add(w.sup.opts.WorkerStartTimeout))
		hello, err := wc.Recv()
		_ = c.SetReadDeadline(time.Time{})
		if err != nil || hello.Type != ipc.MsgHello || hello.Role != w.role {
			_ = wc.Close()
			w.setState(StateDown, "the worker did not introduce itself correctly")
			return nil, false
		}
		caller, err := wc.Caller()
		if err != nil || caller.SID != w.sid {
			_ = wc.Close()
			w.setState(StateDown, "a process that is not the worker's service account connected to its pipe")
			return nil, false
		}
		return wc, true
	}
}

// serve hands the connected worker its current load, then relays results
// until the pipe closes.
func (w *workerMgr) serve(ctx context.Context, wc *ipc.WorkerConn) {
	w.mu.Lock()
	w.conn = wc
	w.mu.Unlock()
	w.setState(StateRunning, "")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			m, err := wc.Recv()
			if err != nil {
				return
			}
			w.mu.Lock()
			ch := w.pending[m.Revision]
			delete(w.pending, m.Revision)
			w.mu.Unlock()
			if ch == nil {
				continue
			}
			if m.Type == ipc.MsgFailed {
				ch <- &loadError{reason: m.Reason, refused: true}
			} else {
				ch <- nil
			}
		}
	}()
	go w.sup.workerConnected(ctx, w.role)

	select {
	case <-ctx.Done():
		// ADR-0006 lifecycle: the worker is told to stop before its pipe
		// closes (R-24); the close alone would also end it.
		_ = wc.Conn().SetWriteDeadline(time.Now().Add(stopSendTimeout))
		_ = wc.Send(ipc.WorkerMsg{Type: ipc.MsgStop})
	case <-done:
		w.setState(StateDown, "the worker stopped")
	}
	// A load still waiting when the worker goes away counts as refused, so
	// the change is undone (R-22); when the supervisor itself is stopping,
	// it applies at the next start instead.
	lost := error(&loadError{reason: "the " + w.role + " worker stopped while applying the change"})
	if ctx.Err() != nil {
		lost = errWorkerDown
	}
	w.mu.Lock()
	w.conn = nil
	for rev, ch := range w.pending {
		ch <- lost
		delete(w.pending, rev)
	}
	w.mu.Unlock()
	_ = wc.Close()
}

// load sends one load and waits for the worker's answer. Revision numbers on
// the wire are per-load sequence numbers, so two loads of the same config
// revision never collide.
func (w *workerMgr) load(m ipc.WorkerMsg) error {
	w.mu.Lock()
	if w.conn == nil {
		w.mu.Unlock()
		return errWorkerDown
	}
	w.nextLoad++
	m.Revision = w.nextLoad
	ch := make(chan error, 1)
	w.pending[m.Revision] = ch
	conn := w.conn
	w.mu.Unlock()

	if err := conn.Send(m); err != nil {
		w.mu.Lock()
		delete(w.pending, m.Revision)
		w.mu.Unlock()
		return fmt.Errorf("sending to the %s worker: %w", w.role, err)
	}
	select {
	case err := <-ch:
		return err
	case <-time.After(w.sup.opts.LoadTimeout):
		w.mu.Lock()
		delete(w.pending, m.Revision)
		w.mu.Unlock()
		// counted as refused, so the change is undone (R-22); the worker
		// handles loads in order, so a restore sent next lands after it
		return &loadError{reason: fmt.Sprintf("the %s worker did not answer in time", w.role)}
	}
}

// stop asks the worker to stop and stops its service.
func (w *workerMgr) stop() {
	w.mu.Lock()
	conn := w.conn
	w.mu.Unlock()
	if conn != nil {
		_ = conn.Send(ipc.WorkerMsg{Type: ipc.MsgStop})
	}
	_ = w.sup.opts.Services.Stop(w.service)
}
