package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
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

// loadError is a worker's own refusal of a load.
type loadError struct{ reason string }

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
			backoff = time.Second
			w.serve(ctx, c)
		}
		if ctx.Err() != nil {
			return
		}
		w.mu.Lock()
		w.restarts++
		w.mu.Unlock()
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
				ch <- &loadError{m.Reason}
			} else {
				ch <- nil
			}
		}
	}()
	go w.sup.workerConnected(ctx, w.role)

	select {
	case <-ctx.Done():
	case <-done:
		w.setState(StateDown, "the worker stopped")
	}
	w.mu.Lock()
	w.conn = nil
	for rev, ch := range w.pending {
		ch <- errWorkerDown
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
		return fmt.Errorf("the %s worker did not answer in time", w.role)
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
