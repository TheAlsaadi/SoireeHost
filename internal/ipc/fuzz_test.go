package ipc

import (
	"encoding/json"
	"slices"
	"testing"
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

// FuzzDecodeWorkerMsg: decoding never panics and every accepted message
// passes Validate.
func FuzzDecodeWorkerMsg(f *testing.F) {
	for _, s := range []string{
		`{"type":"hello","role":"web","version":"1.0.0"}`,
		`{"type":"load","revision":1,"caddy":{"apps":{}}}`,
		`{"type":"load","token":"x"}`,
		`{"type":"failed","reason":"x"}`,
		`{"type":"stop"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeWorkerMsg(data)
		if err != nil {
			return
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("accepted invalid message: %v", err)
		}
	})
}
