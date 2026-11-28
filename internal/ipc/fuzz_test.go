package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
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
		`{"type":"scan","revision":2,"scan":{"root":"C:\\Sites\\blog","allow_well_known":false}}`,
		`{"type":"scanned","revision":2,"exposure":{"findings":[{"path":"keys/a.txt","kind":"private_key","served":true},{"path":".env","kind":"blocked_name","served":false}],"entries":3,"incomplete":false}}`,
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
			if web.Exposure != nil {
				if err := sitecheck.ValidateExposureReport(*web.Exposure); err != nil {
					t.Fatalf("accepted an invalid exposure report: %v", err)
				}
			}
		}
		if terr == nil {
			if err := tun.ValidateFor(RoleTunnel); err != nil {
				t.Fatalf("accepted invalid message: %v", err)
			}
			if tun.Caddy != nil || tun.Scan != nil || tun.Exposure != nil {
				t.Fatal("a web payload accepted on the tunnel pipe")
			}
		}
	})
}

// FuzzReadFrame: the frame parser runs before the caller is identified
// (GOE-13). It never panics, never returns more than MaxFrame, and what it
// accepts is the declared length and writes back as the bytes it read.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 2, '{', '}', 'x'})
	f.Add([]byte{0, 0, 0, 9, '{', '}'})
	f.Add([]byte{0, 0x10, 0, 0})
	f.Add([]byte{0, 0x10, 0, 1})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 'x'})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		payload, err := ReadFrame(r)
		if len(data) >= 4 && binary.BigEndian.Uint32(data) > MaxFrame {
			if !errors.Is(err, ErrFrameTooLarge) || r.Len() != len(data)-4 {
				t.Fatalf("oversized frame: %v, %d bytes of payload read", err, len(data)-4-r.Len())
			}
			return
		}
		if err != nil {
			if len(data) >= 4 && int(binary.BigEndian.Uint32(data)) <= len(data)-4 {
				t.Fatalf("complete frame refused: %v", err)
			}
			return
		}
		if len(payload) > MaxFrame || len(payload) != int(binary.BigEndian.Uint32(data)) {
			t.Fatalf("%d bytes returned", len(payload))
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), data[:len(data)-r.Len()]) {
			t.Fatal("the frame does not write back as it was read")
		}
	})
}

// FuzzDecodeResponse: decoding never panics, and anything accepted holds
// exactly one of a result and an error and decodes again (GOE-13).
func FuzzDecodeResponse(f *testing.F) {
	for _, s := range []string{
		`{"id":1,"result":{}}`,
		`{"id":2,"error":{"code":"invalid","message":"x"}}`,
		`{"id":3,"error":{"code":"confirmation_required","message":"x","confirmation":{}}}`,
		`{"id":4,"result":null}`,
		`{"id":5,"result":{},"error":{"code":"internal","message":"x"}}`,
		`{"id":6}`,
		`{"id":7,"result":{}} {}`,
		`{"id":8,"result":{},"extra":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := DecodeResponse(data)
		if err != nil {
			return
		}
		if (resp.Error == nil) == (len(resp.Result) == 0) {
			t.Fatalf("accepted %q without exactly one of result and error", data)
		}
		again, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeResponse(again); err != nil {
			t.Fatalf("re-encoded response refused: %v\n%s", err, again)
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
		b, err := json.Marshal(WorkerMsg{Type: MsgFailed, Revision: 1, Code: FailOther, Reason: out})
		if err != nil {
			t.Fatal(err)
		}
		m, err := DecodeWorkerMsg(b, RoleWeb)
		if err != nil || m.Reason != out {
			t.Fatalf("did not survive the pipe: %v", err)
		}
	})
}
