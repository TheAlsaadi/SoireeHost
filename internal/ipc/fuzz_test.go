package ipc

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzDecodeRequest: decoding never panics; anything accepted names a known
// method and re-encodes to a request that decodes the same way.
func FuzzDecodeRequest(f *testing.F) {
	for _, s := range []string{
		`{"id":1,"method":"status.get"}`,
		`{"id":2,"method":"config.rollback","params":{"revision":3}}`,
		`{"id":3,"method":"site.put","params":{"site":{"id":"a","name":"A","type":"static","static":{"root":"C:\\x"}},"confirm":true}}`,
		`{"id":4,"method":"secret.set","params":{"name":"tunnel_token","value":"x"}}`,
		`{"id":5,"method":"audit.list","params":{"after":1,"limit":2}}`,
		`{"id":6,"method":"exec.run"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req, params, err := DecodeRequest(data)
		if err != nil {
			return
		}
		if !slices.Contains(Methods(), req.Method) || params == nil {
			t.Fatalf("accepted unknown method %q", req.Method)
		}
		p, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		again, err := json.Marshal(Request{ID: req.ID, Method: req.Method, Params: p})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeRequest(again); err != nil {
			t.Fatalf("re-encoded request refused: %v\n%s", err, again)
		}
	})
}

// FuzzDecodeWorkerMsg: decoding never panics, every accepted message passes
// ValidateFor its pipe's role, and no payload of one role is accepted on the
// other's pipe (SE-21).
func FuzzDecodeWorkerMsg(f *testing.F) {
	for _, s := range []string{
		`{"type":"hello","role":"web","version":"1.0.0"}`,
		`{"type":"load","revision":1,"caddy":{"apps":{}}}`,
		`{"type":"load","tunnel":{"offline":false,"listen_port":8787,"metrics_port":20241,"shares":[{"site_id":"a","port":8788,"metrics_port":20242}]}}`,
		`{"type":"status","report":{"tunnels":[{"kind":"quick","site_id":"a","state":"connected","connections":4,"hostname":"x.trycloudflare.com","since":"2026-11-14T00:00:00Z"}]}}`,
		`{"type":"failed","reason":"x"}`,
		`{"type":"stop"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		web, werr := DecodeWorkerMsg(data, RoleWeb)
		tun, terr := DecodeWorkerMsg(data, RoleTunnel)
		if werr == nil {
			if err := web.ValidateFor(RoleWeb); err != nil {
				t.Fatalf("accepted invalid message: %v", err)
			}
			if web.Tunnel != nil || web.Report != nil {
				t.Fatal("a tunnel payload accepted on the web pipe")
			}
		}
		if terr == nil {
			if err := tun.ValidateFor(RoleTunnel); err != nil {
				t.Fatalf("accepted invalid message: %v", err)
			}
			if tun.Caddy != nil {
				t.Fatal("a Caddy payload accepted on the tunnel pipe")
			}
		}
	})
}

// GO-1: whatever a worker's error says, CutReason turns it into a reason
// that survives JSON and the supervisor's Validate unchanged.
func FuzzCutReason(f *testing.F) {
	f.Add("failed")
	f.Add("")
	f.Add(strings.Repeat("a", MaxReasonLen-1) + "é")
	f.Add("\xff\xfe" + strings.Repeat("語", 1000))
	f.Fuzz(func(t *testing.T, s string) {
		out := CutReason(s)
		if out == "" || len(out) > MaxReasonLen || !utf8.ValidString(out) {
			t.Fatalf("%d bytes, valid %v", len(out), utf8.ValidString(out))
		}
		b, err := json.Marshal(WorkerMsg{Type: MsgFailed, Revision: 1, Reason: out})
		if err != nil {
			t.Fatal(err)
		}
		m, err := DecodeWorkerMsg(b, RoleWeb)
		if err != nil || m.Reason != out {
			t.Fatalf("did not survive the pipe: %v", err)
		}
	})
}
