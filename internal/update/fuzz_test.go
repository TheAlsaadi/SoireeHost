package update

import (
	"bytes"
	"testing"
)

// FuzzVerify: no envelope makes Verify panic, and anything it accepts was
// signed by the trusted key over a payload that passes every check.
func FuzzVerify(f *testing.F) {
	pub, priv := testKey(1)
	payload := mustPayload(f, validManifest())
	env := mustSign(f, payload, priv)
	f.Add(env)
	f.Add(bytes.TrimSpace(env))
	f.Add([]byte(`{"format":1,"key":"","payload":"","sig":""}`))
	f.Add([]byte(`{"format":1,"key":"x","payload":"e30=","sig":"AA=="}`))
	f.Add([]byte(`{"format":1e0}`))
	ks := keySet(pub)
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Verify(data, ks, "1.2.0")
		if err != nil {
			return
		}
		if err := m.Check(); err != nil {
			t.Fatalf("Verify accepted a manifest that Check refuses: %v", err)
		}
		p, err := Open(data, ks)
		if err != nil {
			t.Fatalf("Verify accepted what Open refuses: %v", err)
		}
		if !bytes.Equal(p, payload) {
			t.Fatalf("an envelope verified with a payload the key never signed: %q", p)
		}
	})
}

// FuzzDecodePayload: decoding never panics, and every payload that decodes
// and passes Check survives a round trip through EncodePayload unchanged.
func FuzzDecodePayload(f *testing.F) {
	f.Add(mustPayload(f, validManifest()))
	f.Add([]byte(`{"product":"soireehost","channel":"stable","version":"1.3.0","min_from":"1.0.0","published":"2026-12-01T10:00:00Z","artifact":null}`))
	f.Add([]byte(`{"product":"soireehost","product":"x"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodePayload(data)
		if err != nil || m.Check() != nil {
			return
		}
		p, err := EncodePayload(m)
		if err != nil {
			t.Fatalf("EncodePayload refused a checked manifest: %v", err)
		}
		again, err := DecodePayload(p)
		if err != nil {
			t.Fatalf("re-decoding: %v", err)
		}
		if !again.Published.Equal(m.Published.UTC().Truncate(1e9)) {
			t.Fatalf("published changed: %v then %v", m.Published, again.Published)
		}
		again.Published = m.Published
		if again != m {
			t.Fatalf("round trip changed the manifest: %+v then %+v", m, again)
		}
	})
}

// FuzzParseKeys: key files never panic the parser, and anything accepted
// holds at most two distinct keys whose ids match.
func FuzzParseKeys(f *testing.F) {
	p1, _ := testKey(1)
	p2, _ := testKey(2)
	one, _ := EncodeKeys(p1)
	two, _ := EncodeKeys(p1, p2)
	f.Add(one)
	f.Add(two)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[{"id":"","public":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ks, err := ParseKeys(data)
		if err != nil {
			return
		}
		if len(ks) > maxKeys {
			t.Fatalf("accepted %d keys", len(ks))
		}
		for i, k := range ks {
			if KeyID(k.Public) != k.ID {
				t.Fatalf("key %d: id %q does not match", i, k.ID)
			}
			for _, o := range ks[:i] {
				if o.ID == k.ID {
					t.Fatalf("key %q accepted twice", k.ID)
				}
			}
		}
	})
}
