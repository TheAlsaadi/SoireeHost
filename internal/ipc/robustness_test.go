package ipc

// Regression tests for the IPC findings of the Phases 0-2 skills review
// (docs/reviews/2026-11-12-skills-review.md): DR-3 (memory held by
// unidentified control connections, no connection limit), GO-15 (a handler
// panic ended the process) and GO-1 (a failure reason cut inside a
// character was refused by the supervisor).

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

func heapNow() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// openHeaders opens n connections and sends only a frame header declaring
// size bytes on each.
func openHeaders(t *testing.T, path string, n int, size uint32) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], size)
	for range n {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		c, err := Dial(ctx, path, me(t))
		cancel()
		if err != nil {
			t.Fatalf("connection %d refused: %v", len(conns), err)
		}
		conns = append(conns, c)
		if _, err := c.Write(hdr[:]); err != nil {
			t.Fatal(err)
		}
	}
	return conns
}

// closedByServer reports whether the server has closed c (a read ends with
// an error other than the deadline).
func closedByServer(c net.Conn, wait time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64<<10)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue // the refusal message
		}
		return !errors.Is(err, os.ErrDeadlineExceeded)
	}
}

// DR-3: a caller who may not control SoiréeHost is identified after the
// first frame header and dropped before any payload memory is allocated.
func TestRefusedCallerHoldsNoMemory(t *testing.T) {
	const n = 12
	s := serve(t, func(winsec.Caller) bool { return false })
	base := heapNow()
	conns := openHeaders(t, s.path, n, MaxFrame)
	time.Sleep(time.Second)
	var grown uint64
	if h := heapNow(); h > base {
		grown = h - base
	}
	if limit := uint64(n) * (64 << 10); grown > limit {
		t.Errorf("%d refused connections that declared %d-byte frames hold %d bytes", n, MaxFrame, grown)
	}
	for i, c := range conns {
		if !closedByServer(c, 5*time.Second) {
			t.Errorf("refused connection %d is still open", i)
		}
	}
	select {
	case <-s.calls:
		t.Fatal("handler ran for a refused caller")
	default:
	}
}

// DR-3: a frame declared large but sent slowly holds only what has arrived.
func TestReadFramePayloadGrowsWithData(t *testing.T) {
	if _, err := readFramePayload(strings.NewReader("abc"), MaxFrame); err == nil {
		t.Fatal("short payload accepted")
	}
	b, err := readFramePayload(strings.NewReader("abcdef"), 3)
	if err != nil || string(b) != "abc" {
		t.Fatalf("%q %v", b, err)
	}
}

// DR-3: at most MaxControlConns connections are served at once; the next is
// closed at once, and a freed slot is reused.
func TestControlConnectionLimit(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	held := make([]net.Conn, 0, MaxControlConns)
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	for range MaxControlConns {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		c, err := Dial(ctx, s.path, me(t))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	extra, err := Dial(ctx, s.path, me(t))
	if err == nil {
		if !closedByServer(extra, 3*time.Second) {
			t.Error("a connection over the limit was kept open")
		}
		_ = extra.Close()
	}
	_ = held[0].Close()
	held = held[1:]
	time.Sleep(500 * time.Millisecond)
	c, err := DialControl(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var st StatusResult
	if err := c.Call(ctx, MethodStatus, None{}, &st); err != nil {
		t.Fatalf("a freed slot was not reused: %v", err)
	}
}

// GO-15: a handler that panics fails only its own call; the server keeps
// serving.
func TestHandlerPanicIsContained(t *testing.T) {
	user := me(t)
	path := pipeName(t)
	ln, err := Listen(path, winsec.ControlPipeSDDL(user, user))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeControl(ctx, ln, func(winsec.Caller) bool { return true },
			func(_ context.Context, _ winsec.Caller, method string, _ any) (any, *Error) {
				if method == MethodSiteRemove {
					panic("handler panic")
				}
				return StatusResult{Version: "test", State: "running"}, nil
			})
	}()
	t.Cleanup(func() { cancel(); <-done })
	cctx, ccancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer ccancel()
	c, err := DialControl(cctx, path, user)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var e *Error
	if err := c.Call(cctx, MethodSiteRemove, SiteIDParams{ID: "x"}, nil); !errors.As(err, &e) || e.Code != CodeInternal {
		t.Fatalf("panicking call returned %v", err)
	}
	var st StatusResult
	if err := c.Call(cctx, MethodStatus, None{}, &st); err != nil || st.State != "running" {
		t.Fatalf("call after the panic: %+v %v", st, err)
	}
}

// GO-1: CutReason keeps a reason valid UTF-8 within MaxReasonLen, so it
// survives JSON and the supervisor's Validate.
func TestCutReason(t *testing.T) {
	for name, in := range map[string]string{
		"split character": strings.Repeat("a", MaxReasonLen-1) + "é tail",
		"aligned":         strings.Repeat("a", MaxReasonLen-2) + "é tail",
		"invalid bytes":   strings.Repeat("\xff", MaxReasonLen),
		"wide":            strings.Repeat("語", MaxReasonLen),
		"short":           "failed",
		"empty":           "",
	} {
		out := CutReason(in)
		if out == "" || len(out) > MaxReasonLen || !utf8.ValidString(out) {
			t.Errorf("%s: %d bytes, valid %v", name, len(out), utf8.ValidString(out))
			continue
		}
		b, err := json.Marshal(WorkerMsg{Type: MsgFailed, Revision: 1, Reason: out})
		if err != nil {
			t.Fatal(err)
		}
		var m WorkerMsg
		if err := json.Unmarshal(b, &m); err != nil || m.ValidateFor(RoleWeb) != nil || m.Reason != out {
			t.Errorf("%s: did not survive the pipe: %v %v", name, err, m.ValidateFor(RoleWeb))
		}
	}
}

// GO-1, end to end: a worker whose load fails with a long non-ASCII error
// reaches the supervisor with a failed message it accepts.
func TestFailedReasonReachesSupervisor(t *testing.T) {
	user := me(t)
	path := pipeName(t)
	ln, err := Listen(path, winsec.WorkerPipeSDDL(user, user))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reason := strings.Repeat("a", MaxReasonLen-1) + "é and more text"
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- RunAgent(ctx, AgentOptions{
			Pipe: path, SupervisorSID: user, Role: RoleWeb, Version: "test",
			Load: func(WorkerMsg) error { return errors.New(reason) },
		})
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	sup := NewWorkerConn(c, RoleWeb)
	defer func() { _ = sup.Close() }()
	if m, err := sup.Recv(); err != nil || m.Type != MsgHello {
		t.Fatalf("hello: %v %v", m, err)
	}
	if err := sup.Send(WorkerMsg{Type: MsgLoad, Revision: 7, Caddy: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	m, err := sup.Recv()
	_ = sup.Close()
	cancel()
	if aerr := <-agentDone; aerr != nil {
		t.Errorf("agent ended with %v", aerr)
	}
	if err != nil || m.Type != MsgFailed || m.Revision != 7 {
		t.Fatalf("supervisor got %v, %v", m, err)
	}
}

// R-05: a load error that wraps ErrAgentExit is reported to the supervisor,
// and then the agent returns, so the worker process ends.
func TestAgentExitsAfterFatalLoad(t *testing.T) {
	user := me(t)
	path := pipeName(t)
	ln, err := Listen(path, winsec.WorkerPipeSDDL(user, user))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- RunAgent(ctx, AgentOptions{
			Pipe: path, SupervisorSID: user, Role: RoleWeb, Version: "test",
			Load: func(WorkerMsg) error { return fmt.Errorf("%w: self-check failed", ErrAgentExit) },
		})
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	sup := NewWorkerConn(c, RoleWeb)
	defer func() { _ = sup.Close() }()
	if m, err := sup.Recv(); err != nil || m.Type != MsgHello {
		t.Fatalf("hello: %v %v", m, err)
	}
	if err := sup.Send(WorkerMsg{Type: MsgLoad, Revision: 3, Caddy: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if m, err := sup.Recv(); err != nil || m.Type != MsgFailed || m.Revision != 3 {
		t.Fatalf("supervisor got %v, %v", m, err)
	}
	select {
	case err := <-agentDone:
		if !errors.Is(err, ErrAgentExit) {
			t.Fatalf("agent ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept running after a load that requires it to exit")
	}
}
