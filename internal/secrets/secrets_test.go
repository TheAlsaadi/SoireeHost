package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// S-40: the value round-trips, and what lands on disk is not the value.
func TestSetGetEncrypted(t *testing.T) {
	s := newStore(t)
	value := []byte("CANARY-eyJhIjoiIn0-tunnel-token")
	fixed := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	if err := s.Set(TunnelToken, value); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(TunnelToken)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if bytes.Contains(b, value) || bytes.Contains(b, []byte("CANARY")) {
			t.Errorf("%s contains the secret in clear", e.Name())
		}
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
	st, err := s.Status(TunnelToken)
	if err != nil || !st.Set || !st.SetAt.Equal(fixed) {
		t.Fatalf("status %+v, %v", st, err)
	}
}

// S-35: status never carries the value.
func TestStatusHasNoValue(t *testing.T) {
	s := newStore(t)
	st, err := s.Status(TunnelToken)
	if err != nil || st.Set {
		t.Fatalf("unset status %+v, %v", st, err)
	}
	if err := s.Set(TunnelToken, []byte("CANARY-x")); err != nil {
		t.Fatal(err)
	}
	st, _ = s.Status(TunnelToken)
	if strings.Contains(strings.ToLower(st.Name+st.SetAt.String()), "canary") {
		t.Fatal("status leaks the value")
	}
}

func TestTamperedBlobRefused(t *testing.T) {
	s := newStore(t)
	if err := s.Set(TunnelToken, []byte("value")); err != nil {
		t.Fatal(err)
	}
	p := s.blobPath(TunnelToken)
	b, _ := os.ReadFile(p) //nolint:gosec // G304: the test store's own file
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // G703: the test store's own file
		t.Fatal(err)
	}
	if _, err := s.Get(TunnelToken); err == nil {
		t.Fatal("tampered blob decrypted")
	}
}

func TestReplaceAndRemove(t *testing.T) {
	s := newStore(t)
	_ = s.Set(TunnelToken, []byte("one"))
	_ = s.Set(TunnelToken, []byte("two"))
	if got, _ := s.Get(TunnelToken); string(got) != "two" {
		t.Fatalf("got %q", got)
	}
	if err := s.Remove(TunnelToken); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(TunnelToken); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := s.Get(TunnelToken); err == nil {
		t.Fatal("removed secret still readable")
	}
}

func TestRejectsBadInput(t *testing.T) {
	s := newStore(t)
	for _, name := range []string{"", `..\x`, "a/b", "Tunnel", "x.bin", strings.Repeat("a", 40)} {
		if err := s.Set(name, []byte("v")); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if err := s.Set(TunnelToken, nil); err == nil {
		t.Error("empty value accepted")
	}
	if err := s.Set(TunnelToken, make([]byte, MaxValueLen+1)); err == nil {
		t.Error("oversized value accepted")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing folder accepted")
	}
}
