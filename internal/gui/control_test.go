package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// fakeSupervisor records every call and answers from a function.
type fakeSupervisor struct {
	calls  []string
	params []any
	answer func(method string, params any) (any, error)
}

func (f *fakeSupervisor) Call(_ context.Context, method string, params, out any) error {
	f.calls = append(f.calls, method)
	f.params = append(f.params, params)
	res, err := f.answer(method, params)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(res)
	return json.Unmarshal(b, out)
}

// The bindings pass each call through unchanged: the supervisor does all
// validation (S-31), and a confirmation token goes back exactly as given.
func TestControlPassesCallsThrough(t *testing.T) {
	f := &fakeSupervisor{answer: func(string, any) (any, error) { return ipc.ConfigResult{Revision: 3}, nil }}
	c := NewControl(f)
	site := config.Site{ID: "blog"}
	if res, err := c.PutSite(t.Context(), site, "tok"); err != nil || res.Revision != 3 {
		t.Fatalf("PutSite: %+v %v", res, err)
	}
	if got := f.params[0].(ipc.SitePutParams); got.Site.ID != "blog" || got.Confirmation != "tok" {
		t.Fatalf("params changed on the way: %+v", got)
	}
	if _, err := c.SetSiteEnabled(t.Context(), "blog", true, ""); err != nil || f.calls[1] != ipc.MethodSiteSetEnabled {
		t.Fatal(f.calls, err)
	}
}

// S-35: the token passes through once and is never kept or returned.
func TestTunnelTokenIsWriteOnly(t *testing.T) {
	const canary = "eyJhIjoiY2FuYXJ5LXRva2VuLWZvci1zLTM1In0="
	f := &fakeSupervisor{answer: func(string, any) (any, error) {
		return ipc.SecretStatusResult{Secrets: []ipc.SecretStatus{{Name: "tunnel_token", Set: true}}}, nil
	}}
	c := NewControl(f)
	res, err := c.SetTunnelToken(t.Context(), canary, "")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), canary) {
		t.Fatal("the token came back to the UI")
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c); strings.Contains(s, canary) {
		t.Fatal("the service kept the token")
	}
	if s := fmt.Sprintf("%v %#v", f.params[0], f.params[0]); strings.Contains(s, canary) {
		t.Fatal("the params print the token")
	}
	// no bound method can read a secret back
	for m := range reflect.TypeOf(c).Methods() {
		m := m
		for out := range m.Type.Outs() {
			if out := out; out == reflect.TypeFor[ipc.SecretSetParams]() {
				t.Errorf("%s returns secret params", m.Name)
			}
		}
	}
}

// The supervisor's error reaches the UI whole, with its confirmation offer
// and worker detail; anything else becomes a plain "unavailable".
func TestMarshalError(t *testing.T) {
	in := &ipc.Error{Code: ipc.CodeConfirmationRequired, Message: "Confirm.", WorkerDetail: "port busy",
		Confirmation: &ipc.Confirmation{Token: "abc", Sentences: []string{"Weaker."}}}
	var got ipc.Error
	if err := json.Unmarshal(marshalError(fmt.Errorf("wrapped: %w", in)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != in.Code || got.Confirmation == nil || got.Confirmation.Token != "abc" || got.WorkerDetail != "port busy" {
		t.Fatalf("lost detail: %+v", got)
	}
	_ = json.Unmarshal(marshalError(errors.New(`open \\.\pipe\soireehost-control-0123: access denied`)), &got)
	if got.Code != ipc.CodeUnavailable || strings.Contains(got.Message, "pipe") {
		t.Fatalf("an internal error reached the UI: %+v", got)
	}
}

// An import is confirmed for exactly what was read; a confirmation with no
// import waiting, or a second confirmation, is refused.
func TestImportConfirmsWhatWasRead(t *testing.T) {
	f := &fakeSupervisor{answer: func(_ string, p any) (any, error) {
		if p.(ipc.ConfigImportParams).Confirmation == "" {
			return nil, &ipc.Error{Code: ipc.CodeConfirmationRequired, Confirmation: &ipc.Confirmation{Token: "t1"}}
		}
		return ipc.ConfigResult{Revision: 9}, nil
	}}
	c := NewControl(f)
	if _, err := c.ConfirmImport(t.Context(), "t1"); !errors.Is(err, errNoImport) {
		t.Fatalf("confirmation with nothing waiting: %v", err)
	}
	if _, err := c.ImportConfig(t.Context(), "not json"); err == nil {
		t.Fatal("garbage imported")
	}
	text := `{"version":1,"listen":"127.0.0.1:8787","sites":[]}`
	var e *ipc.Error
	if _, err := c.ImportConfig(t.Context(), text); !errors.As(err, &e) || e.Confirmation.Token != "t1" {
		t.Fatalf("first import call: %v", err)
	}
	if res, err := c.ConfirmImport(t.Context(), "t1"); err != nil || res.Revision != 9 {
		t.Fatalf("confirm: %+v %v", res, err)
	}
	last := f.params[len(f.params)-1].(ipc.ConfigImportParams)
	if last.Config.Listen != "127.0.0.1:8787" || last.Confirmation != "t1" {
		t.Fatalf("confirmed something else: %+v", last)
	}
	if _, err := c.ConfirmImport(t.Context(), "t1"); !errors.Is(err, errNoImport) {
		t.Fatal("an import was confirmed twice")
	}
	if _, err := c.ImportConfig(t.Context(), strings.Repeat(" ", config.MaxConfigBytes+1)); err == nil {
		t.Fatal("an oversized file was read")
	}
}

// S-33: every response of the asset server carries the CSP, and it is the
// same policy as the page's meta tag.
func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x")) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/index.js", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP allows %q: %s", bad, csp)
		}
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff missing")
	}
}

func TestParseArgs(t *testing.T) {
	if o, err := ParseArgs([]string{"--tray"}); err != nil || !o.Tray {
		t.Fatal(o, err)
	}
	if o, err := ParseArgs(nil); err != nil || o.Tray {
		t.Fatal(o, err)
	}
	for _, bad := range [][]string{{"--devtools"}, {"--url=https://example.com"}, {"tray"}} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTrayLine(t *testing.T) {
	if l, on := trayLine(ipc.StatusResult{}, errors.New("down")); on || !strings.Contains(l, "not answering") {
		t.Error(l)
	}
	st := ipc.StatusResult{Tunnel: ipc.TunnelStatus{Tunnels: []ipc.TunnelView{{State: ipc.TunnelConnected}}}}
	if l, on := trayLine(st, nil); !on || !strings.Contains(l, "online") {
		t.Error(l)
	}
	st.Tunnel.Offline = true
	if l, on := trayLine(st, nil); on || !strings.Contains(l, "offline") {
		t.Error(l)
	}
}
