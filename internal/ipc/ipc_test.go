package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("%q %v", got, err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
	// a huge length is refused before any payload is read
	r := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(r); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized read: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 5, 'a'})); err == nil {
		t.Fatal("short frame accepted")
	}
}

func TestDecodeRequest(t *testing.T) {
	good := map[string]string{ //nolint:gosec // G101: test requests with a fake token
		"status":      `{"id":1,"method":"status.get"}`,
		"status null": `{"id":1,"method":"status.get","params":null}`,
		"rollback":    `{"id":2,"method":"config.rollback","params":{"revision":3}}`,
		"site.put":    `{"id":3,"method":"site.put","params":{"site":{"id":"a","name":"A","enabled":true,"hostnames":["a.example.com"],"type":"proxy","proxy":{"target":"127.0.0.1:3000","allow_lan":false},"max_body_bytes":0,"rate_limit_per_minute":0,"allow_well_known":false},"confirm":false}}`,
		"secret.set":  `{"id":4,"method":"secret.set","params":{"name":"tunnel_token","value":"x","confirm":true}}`,
		"audit":       `{"id":5,"method":"audit.list","params":{"after":0,"limit":10}}`,
	}
	for name, in := range good {
		if _, _, err := DecodeRequest([]byte(in)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	bad := map[string]string{
		"unknown method":      `{"id":1,"method":"exec.run","params":{"cmd":"calc"}}`,
		"unknown top field":   `{"id":1,"method":"status.get","sudo":true}`,
		"unknown param field": `{"id":1,"method":"config.rollback","params":{"revision":1,"path":"C:\\x"}}`,
		"params for none":     `{"id":1,"method":"status.get","params":{"x":1}}`,
		"wrong type":          `{"id":1,"method":"config.rollback","params":{"revision":"1"}}`,
		"trailing data":       `{"id":1,"method":"status.get"}{}`,
		"not an object":       `[]`,
		"empty":               ``,
		"negative id":         `{"id":-1,"method":"status.get"}`,
		"site field unknown":  `{"id":3,"method":"site.put","params":{"site":{"id":"a","port_forward":true}}}`,
	}
	for name, in := range bad {
		if _, _, err := DecodeRequest([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDecodeResponse(t *testing.T) {
	if _, err := DecodeResponse([]byte(`{"id":1,"result":{}}`)); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{`{"id":1}`, `{"id":1,"result":{},"error":{"code":"x","message":"y"}}`, `{"id":1,"result":{},"x":1}`} {
		if _, err := DecodeResponse([]byte(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

func TestWorkerMsgValidate(t *testing.T) {
	good := []WorkerMsg{
		{Type: MsgHello, Role: RoleWeb, Version: "1.0.0"},
		{Type: MsgLoad, Revision: 3, Caddy: json.RawMessage(`{}`)},
		{Type: MsgLoad, Token: "t"},
		{Type: MsgLoaded, Revision: 3},
		{Type: MsgFailed, Reason: "port in use"},
		{Type: MsgStop},
	}
	for _, m := range good {
		if err := m.Validate(); err != nil {
			t.Errorf("%v refused: %v", m, err)
		}
	}
	bad := []WorkerMsg{
		{Type: "exec"},
		{Type: MsgHello, Role: "admin"},
		{Type: MsgHello, Role: RoleWeb, Token: "t"},
		{Type: MsgLoad},
		{Type: MsgLoad, Caddy: json.RawMessage(`{}`), Token: "t"},
		{Type: MsgFailed},
		{Type: MsgFailed, Reason: strings.Repeat("x", MaxReasonLen+1)},
		{Type: MsgStop, Token: "t"},
		{Type: MsgLoaded, Token: "t"},
	}
	for _, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("%v accepted", m)
		}
	}
}

// S-40 and S-35: printing a message or params never shows a token.
func TestSecretsNotPrinted(t *testing.T) {
	const canary = "CANARY-TOKEN-1234"
	m := WorkerMsg{Type: MsgLoad, Token: canary}
	p := SecretSetParams{Name: "tunnel_token", Value: canary}
	for _, s := range []string{fmt.Sprint(m), fmt.Sprintf("%v %+v %#v %s", m, m, m, m), fmt.Sprintf("%v %+v %#v %s", p, p, p, p)} {
		if strings.Contains(s, canary) {
			t.Errorf("printed secret: %s", s)
		}
	}
}

func pipeName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return `\\.\pipe\soireehost-test-` + hex.EncodeToString(b)
}

func me(t *testing.T) string {
	t.Helper()
	c, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	return c.SID
}

type served struct {
	path   string
	cancel context.CancelFunc
	calls  chan winsec.Caller
}

func serve(t *testing.T, auth Authorizer) *served {
	t.Helper()
	user := me(t)
	path := pipeName(t)
	ln, err := Listen(path, winsec.ControlPipeSDDL(user, user))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &served{path: path, cancel: cancel, calls: make(chan winsec.Caller, 10)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeControl(ctx, ln, auth, func(_ context.Context, c winsec.Caller, method string, params any) (any, *Error) {
			s.calls <- c
			switch method {
			case MethodStatus:
				return StatusResult{Version: "test", State: "running"}, nil
			case MethodConfigRollback:
				return nil, Errorf(CodeNotFound, "revision %d is not kept", params.(*RollbackParams).Revision)
			}
			return None{}, nil
		})
	}()
	t.Cleanup(func() { cancel(); <-done })
	return s
}

func TestControlRoundTrip(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c, err := DialControl(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var st StatusResult
	if err := c.Call(ctx, MethodStatus, None{}, &st); err != nil || st.State != "running" {
		t.Fatalf("status %+v, %v", st, err)
	}
	caller := <-s.calls
	if caller.SID != me(t) {
		t.Fatalf("server saw caller %s", caller.SID)
	}
	var e *Error
	if err := c.Call(ctx, MethodConfigRollback, RollbackParams{Revision: 9}, nil); !errors.As(err, &e) || e.Code != CodeNotFound {
		t.Fatalf("error result: %v", err)
	}
}

// S-30: an unauthorised caller gets nothing.
func TestControlForbidden(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return false })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c, err := DialControl(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var e *Error
	if err := c.Call(ctx, MethodStatus, None{}, nil); !errors.As(err, &e) || e.Code != CodeForbidden {
		t.Fatalf("unauthorised call: %v", err)
	}
	select {
	case <-s.calls:
		t.Fatal("handler ran for an unauthorised caller")
	default:
	}
}

// ADR-0006: a client refuses a pipe not owned by the supervisor's account,
// so a squatter never receives a request (or a tunnel token).
func TestDialRefusesWrongOwner(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := DialControl(ctx, s.path, winsec.ServiceSID(winsec.SupervisorService)); err == nil {
		t.Fatal("connected to a pipe owned by someone else")
	}
	select {
	case <-s.calls:
		t.Fatal("a request reached the squatter")
	default:
	}
}

// The first instance is exclusive: a second server cannot share the name.
func TestListenExclusive(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	if ln, err := Listen(s.path, winsec.ControlPipeSDDL(me(t), me(t))); err == nil {
		_ = ln.Close()
		t.Fatal("second listener on the same name")
	}
}

// SE-35: an empty descriptor would mean the default pipe ACL, so Listen
// refuses it.
func TestListenRefusesEmptySDDL(t *testing.T) {
	if ln, err := Listen(pipeName(t), ""); err == nil {
		_ = ln.Close()
		t.Fatal("pipe created with the default ACL")
	}
}

func TestMalformedRequestEndsConnection(t *testing.T) {
	s := serve(t, func(winsec.Caller) bool { return true })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, s.path, me(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = WriteFrame(conn, []byte(`{"id":1,"method":"exec.run"}`))
	frame, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := DecodeResponse(frame)
	if resp.Error == nil || resp.Error.Code != CodeInvalid {
		t.Fatalf("response %+v", resp)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ReadFrame(conn); err == nil {
		t.Fatal("connection still open after a malformed request")
	}
}

func TestWorkerPipe(t *testing.T) {
	user := me(t)
	path := pipeName(t)
	ln, err := Listen(path, winsec.WorkerPipeSDDL(user, user))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan WorkerMsg, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		wc := NewWorkerConn(c)
		m, _ := wc.Recv()
		got <- m
		_ = wc.Send(WorkerMsg{Type: MsgLoad, Revision: 1, Caddy: json.RawMessage(`{"apps":{}}`)})
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, path, user)
	if err != nil {
		t.Fatal(err)
	}
	wc := NewWorkerConn(conn)
	defer func() { _ = wc.Close() }()
	if err := wc.Send(WorkerMsg{Type: MsgHello, Role: RoleWeb}); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.Type != MsgHello || m.Role != RoleWeb {
		t.Fatalf("server got %v", m)
	}
	m, err := wc.Recv()
	if err != nil || m.Type != MsgLoad || m.Revision != 1 {
		t.Fatalf("worker got %v, %v", m, err)
	}
	if err := wc.Send(WorkerMsg{Type: "exec"}); err == nil {
		t.Fatal("sent an invalid message")
	}
}
