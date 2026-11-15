package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// rawServer accepts control connections and answers each request with
// reply(n, req), where n counts connections from 1. A nil answer sends
// nothing and keeps the connection open.
type rawServer struct {
	path    string
	accepts atomic.Int32
}

func serveRaw(t *testing.T, reply func(conn int32, req Request) *Response) *rawServer {
	t.Helper()
	path := pipeName(t)
	ln, err := Listen(path, winsec.ControlPipeSDDL(me(t), me(t)))
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{path: path}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := s.accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close() //nolint:errcheck // test server
				for {
					frame, err := ReadFrame(conn)
					if err != nil {
						return
					}
					var req Request
					if err := json.Unmarshal(frame, &req); err != nil {
						return
					}
					resp := reply(n, req)
					if resp == nil {
						continue
					}
					if err := writeResponse(conn, *resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func okResult(id uint64) *Response {
	return &Response{ID: id, Result: json.RawMessage(`{"version":"test","state":"running","revision":0,"workers":null,"audit_ok":true,"started_at":"0001-01-01T00:00:00Z","tunnel":{"offline":false,"token_set":false,"service_url":"","repair_needed":false,"tunnels":null}}`)}
}

// SE-30: an error answer whose ID is not the request's is refused before its
// error is looked at, and the connection is not used again.
func TestClientChecksReplyIDFirst(t *testing.T) {
	s := serveRaw(t, func(conn int32, req Request) *Response {
		if conn == 1 {
			return &Response{ID: req.ID + 7, Error: Errorf(CodeForbidden, "stale answer")}
		}
		return okResult(req.ID)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c, err := DialControl(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	err = c.Call(ctx, MethodStatus, None{}, nil)
	var e *Error
	if err == nil || errors.As(err, &e) {
		t.Fatalf("a mismatched error answer was accepted: %v", err)
	}
	var st StatusResult
	if err := c.Call(ctx, MethodStatus, None{}, &st); err != nil || st.State != "running" {
		t.Fatalf("the call after a mismatch did not reconnect: %+v, %v", st, err)
	}
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("connections = %d, want 2 (the out-of-step one dropped)", got)
	}
}

// SE-30: a call with no deadline ends when its context is cancelled, and the
// connection is dropped.
func TestClientHonoursCancellation(t *testing.T) {
	s := serveRaw(t, func(conn int32, req Request) *Response {
		if conn == 1 {
			return nil // never answer
		}
		return okResult(req.ID)
	})
	c := NewClient(func(ctx context.Context) (net.Conn, error) { return Dial(ctx, s.path, me(t)) })
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	if err := c.Call(ctx, MethodStatus, None{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call returned %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("cancellation took %v", d)
	}
	ctx2, cancel2 := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel2()
	if err := c.Call(ctx2, MethodStatus, None{}, nil); err != nil {
		t.Fatalf("call after cancellation: %v", err)
	}
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("connections = %d, want 2", got)
	}
}

// SE-30: a timed-out call leaves no late answer behind to be read by the
// next call.
func TestClientDropsConnectionAfterTimeout(t *testing.T) {
	s := serveRaw(t, func(conn int32, req Request) *Response {
		if conn == 1 {
			time.Sleep(700 * time.Millisecond) // answers after the caller gave up
		}
		return okResult(req.ID)
	})
	c := NewClient(func(ctx context.Context) (net.Conn, error) { return Dial(ctx, s.path, me(t)) })
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, MethodStatus, None{}, nil); err == nil {
		t.Fatal("call past its deadline succeeded")
	}
	time.Sleep(800 * time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel2()
	if err := c.Call(ctx2, MethodStatus, None{}, nil); err != nil {
		t.Fatalf("call after timeout: %v", err)
	}
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("connections = %d, want 2", got)
	}
}

// An error answer from the supervisor keeps the connection: both ends are
// still in step.
func TestClientKeepsConnectionAfterErrorAnswer(t *testing.T) {
	s := serveRaw(t, func(_ int32, req Request) *Response {
		if req.Method == MethodConfigRollback {
			return &Response{ID: req.ID, Error: Errorf(CodeNotFound, "no such revision")}
		}
		return okResult(req.ID)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c, err := DialControl(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var e *Error
	if err := c.Call(ctx, MethodConfigRollback, RollbackParams{Revision: 3}, nil); !errors.As(err, &e) || e.Code != CodeNotFound {
		t.Fatalf("error answer: %v", err)
	}
	if err := c.Call(ctx, MethodStatus, None{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := s.accepts.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1", got)
	}
	_ = c.Close()
	if err := c.Call(ctx, MethodStatus, None{}, nil); !errors.Is(err, errClientClosed) {
		t.Fatalf("call on a closed client: %v", err)
	}
}
