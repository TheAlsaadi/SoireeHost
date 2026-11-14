package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// IdleTimeout closes a control connection that sends nothing for this long.
const IdleTimeout = 5 * time.Minute

// MaxControlConns bounds the control connections served at once; further
// connections are closed at once (review finding DR-3).
const MaxControlConns = 16

// handleOf returns the Windows handle of a go-winio pipe connection.
func handleOf(c net.Conn) (windows.Handle, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("not a pipe connection")
	}
	return windows.Handle(f.Fd()), nil
}

// Listen creates the first instance of a pipe with the given security
// descriptor. go-winio creates it exclusively (it fails if the name already
// exists, so a squatter makes the supervisor refuse to start rather than
// share the name) and rejects remote clients.
func Listen(path, sddl string) (net.Listener, error) {
	// An empty descriptor would fall back to the default pipe ACL, which
	// lets Everyone and Anonymous read (review finding SE-35).
	if sddl == "" {
		return nil, fmt.Errorf("creating pipe %s: no security descriptor given", path)
	}
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
	if err != nil {
		return nil, fmt.Errorf("creating pipe %s (is another program using the name?): %w", path, err)
	}
	return l, nil
}

// Dial connects to a pipe at Identification level, so the server can read
// who we are but cannot act as us, and then refuses the connection unless the
// pipe is owned by wantOwner (a SID string). Only a process running as that
// account can own the pipe, so this defeats pipe squatting (ADR-0006).
func Dial(ctx context.Context, path, wantOwner string) (net.Conn, error) {
	conn, err := winio.DialPipeAccessImpLevel(ctx, path, winsec.PipeClientAccess, winio.PipeImpLevelIdentification)
	if err != nil {
		return nil, err
	}
	h, err := handleOf(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	owner, err := winsec.HandleOwner(h)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if owner != wantOwner {
		_ = conn.Close()
		return nil, fmt.Errorf("%s is owned by %s, not by SoiréeHost's service; refusing to use it", path, owner)
	}
	return conn, nil
}

// Handler answers one control call. params is the method's decoded params
// type. It returns a result to encode as JSON, or an error.
type Handler func(ctx context.Context, caller winsec.Caller, method string, params any) (any, *Error)

// Authorizer decides whether a caller may use the control API at all.
type Authorizer func(winsec.Caller) bool

// ServeControl accepts control connections until ctx ends or ln is closed.
func ServeControl(ctx context.Context, ln net.Listener, auth Authorizer, h Handler) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	slots := make(chan struct{}, MaxControlConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			serveConn(ctx, conn, auth, h)
		}()
	}
}

func serveConn(ctx context.Context, conn net.Conn, auth Authorizer, h Handler) {
	defer conn.Close() //nolint:errcheck // the client sees the close either way
	// When the supervisor stops, open connections close at once instead of
	// holding its exit for up to IdleTimeout (review finding R-24).
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()
	handle, err := handleOf(conn)
	if err != nil {
		return
	}
	var caller winsec.Caller
	identified := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, err := readFrameHeader(conn)
		if err != nil {
			return
		}
		// Windows lets a pipe server identify its client only after it has
		// read from the pipe, so the check runs after the first frame's
		// header, before any of its payload is read or acted on (DR-3).
		if !identified {
			caller, err = winsec.PipeCaller(handle)
			if err != nil || !auth(caller) {
				_ = writeResponse(conn, Response{Error: Errorf(CodeForbidden, "this account may not control SoiréeHost")})
				return
			}
			identified = true
		}
		frame, err := readFramePayload(conn, n)
		if err != nil {
			return
		}
		req, params, derr := DecodeRequest(frame)
		var resp Response
		resp.ID = req.ID
		if derr != nil {
			// one malformed request ends the connection
			resp.Error = Errorf(CodeInvalid, "%v", derr)
			_ = writeResponse(conn, resp)
			return
		}
		result, herr := callHandler(ctx, h, caller, req.Method, params)
		if herr != nil {
			resp.Error = herr
		} else {
			b, err := json.Marshal(result)
			if err != nil {
				resp.Error = Errorf(CodeInternal, "could not encode the answer")
			} else {
				resp.Result = b
			}
		}
		if err := writeResponse(conn, resp); err != nil {
			return
		}
	}
}

// callHandler runs one control handler and turns a panic into an internal
// error for that call, so one faulty handler cannot end the supervisor and,
// with it, both workers (review finding GO-15). The panic value is not
// returned: it could carry anything the handler held.
func callHandler(ctx context.Context, h Handler, caller winsec.Caller, method string, params any) (result any, herr *Error) {
	defer func() {
		if r := recover(); r != nil {
			result, herr = nil, Errorf(CodeInternal, "internal error while handling %s", method)
		}
	}()
	return h(ctx, caller, method, params)
}

func writeResponse(conn net.Conn, resp Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		b, _ = json.Marshal(Response{ID: resp.ID, Error: Errorf(CodeInternal, "the answer is too large")})
	}
	return WriteFrame(conn, b)
}

// Client is the control panel's connection to the supervisor.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	next uint64
}

// DialControl connects to the control pipe at path and checks that the
// supervisor's service account owns it.
func DialControl(ctx context.Context, path, supervisorSID string) (*Client, error) {
	conn, err := Dial(ctx, path, supervisorSID)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends one request and decodes the result into out (which may be nil).
// A supervisor error comes back as *Error.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	b, err := json.Marshal(Request{ID: c.next, Method: method, Params: p})
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
		defer c.conn.SetDeadline(time.Time{}) //nolint:errcheck // best effort reset
	}
	if err := WriteFrame(c.conn, b); err != nil {
		return err
	}
	frame, err := ReadFrame(c.conn)
	if err != nil {
		return err
	}
	resp, err := DecodeResponse(frame)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if resp.ID != c.next {
		return errors.New("answer does not match the request")
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, out)
}

// WorkerConn is one end of a worker pipe.
type WorkerConn struct {
	conn net.Conn
	wmu  sync.Mutex
}

// NewWorkerConn wraps an established pipe connection.
func NewWorkerConn(c net.Conn) *WorkerConn { return &WorkerConn{conn: c} }

// Send validates and writes one message.
func (w *WorkerConn) Send(m WorkerMsg) error {
	if err := m.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return WriteFrame(w.conn, b)
}

// Recv reads and validates one message.
func (w *WorkerConn) Recv() (WorkerMsg, error) {
	b, err := ReadFrame(w.conn)
	if err != nil {
		return WorkerMsg{}, err
	}
	return DecodeWorkerMsg(b)
}

// Close closes the pipe.
func (w *WorkerConn) Close() error { return w.conn.Close() }

// Conn returns the underlying connection.
func (w *WorkerConn) Conn() net.Conn { return w.conn }

// Caller identifies the client end of a server-side worker connection. Call
// it only after a message has been received.
func (w *WorkerConn) Caller() (winsec.Caller, error) {
	h, err := handleOf(w.conn)
	if err != nil {
		return winsec.Caller{}, err
	}
	return winsec.PipeCaller(h)
}
