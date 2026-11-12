package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func plainWrite(path string, data []byte) error { return os.WriteFile(path, data, 0o600) } //nolint:gosec // G703: paths are the test store's own

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir(), plainWrite)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) }
	return s
}

func withSite(id string) Config {
	c := Default()
	c.Sites = []Site{{ID: id, Name: id, Enabled: true, Hostnames: []string{id + ".example.com"},
		Type: TypeProxy, Proxy: &Proxy{Target: "127.0.0.1:3000"}}}
	return c
}

func TestStoreSaveAndHistory(t *testing.T) {
	s := newStore(t)
	if _, err := s.Current(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("empty store: %v", err)
	}
	for i, id := range []string{"a", "b", "c"} {
		rec, err := s.Save(withSite(id), "S-1-5-21-1", "add "+id)
		if err != nil || rec.Revision != uint64(i+1) {
			t.Fatalf("save %s: rev %d, %v", id, rec.Revision, err)
		}
	}
	cur, err := s.Current()
	if err != nil || cur.Revision != 3 || cur.Config.Sites[0].ID != "c" || cur.Actor != "S-1-5-21-1" {
		t.Fatalf("current %+v, %v", cur, err)
	}
	h, _ := s.History()
	if len(h) != 3 || h[0].Revision != 3 || h[2].Revision != 1 || len(h[0].Config.Sites) != 0 {
		t.Fatalf("history %+v", h)
	}
}

// S-41: invalid configs never reach the disk.
func TestStoreRefusesInvalid(t *testing.T) {
	s := newStore(t)
	bad := withSite("a")
	bad.Listen = "0.0.0.0:8787"
	if _, err := s.Save(bad, "x", "bad"); err == nil {
		t.Fatal("saved an invalid config")
	}
	if _, err := s.Current(); !errors.Is(err, ErrNoConfig) {
		t.Fatal("invalid config written")
	}
}

func TestStoreRollbackAndGood(t *testing.T) {
	s := newStore(t)
	_, _ = s.Save(withSite("a"), "x", "a")
	_ = s.MarkGood(1)
	_, _ = s.Save(withSite("b"), "x", "b")
	if s.LastGood() != 1 {
		t.Fatalf("last good %d", s.LastGood())
	}
	rec, err := s.Rollback(1, "S-1-5-18")
	if err != nil || rec.Revision != 3 || rec.Config.Sites[0].ID != "a" || !strings.Contains(rec.Summary, "revision 1") {
		t.Fatalf("rollback %+v, %v", rec, err)
	}
	if _, err := s.Rollback(99, "x"); err == nil {
		t.Fatal("rolled back to a revision that does not exist")
	}
}

func TestStoreKeepsTenAndGood(t *testing.T) {
	s := newStore(t)
	_, _ = s.Save(withSite("first"), "x", "first")
	_ = s.MarkGood(1)
	for i := range 15 {
		if _, err := s.Save(withSite("s"+string(rune('a'+i))), "x", "more"); err != nil {
			t.Fatal(err)
		}
	}
	revs := s.historyRevisions()
	if len(revs) != HistoryKept+1 || revs[len(revs)-1] != 1 {
		t.Fatalf("history kept %v", revs)
	}
	if _, err := s.Get(1); err != nil {
		t.Fatalf("last good revision pruned: %v", err)
	}
}

// A tampered or damaged current file is refused, and the next save moves it
// aside instead of trusting it.
func TestStoreDamagedCurrent(t *testing.T) {
	s := newStore(t)
	_, _ = s.Save(withSite("a"), "x", "a")
	p := filepath.Join(s.dir, "current.json")
	b, _ := os.ReadFile(p) //nolint:gosec // G304: the test store's own file
	tampered := strings.Replace(string(b), `"127.0.0.1:3000"`, `"169.254.169.254:80"`, 1)
	if err := os.WriteFile(p, []byte(tampered), 0o600); err != nil { //nolint:gosec // G703: the test store's own file
		t.Fatal(err)
	}
	if _, err := s.Current(); err == nil {
		t.Fatal("tampered config accepted")
	}
	rec, err := s.Save(withSite("b"), "x", "b")
	if err != nil || rec.Revision != 2 {
		t.Fatalf("save after damage: %+v %v", rec, err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.dir, "history"))
	found := false
	for _, e := range entries {
		found = found || strings.HasPrefix(e.Name(), "damaged-")
	}
	if !found {
		t.Fatal("damaged file not kept aside")
	}
	if err := os.WriteFile(p, []byte(`{"revision":1,"config":{},"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(); err == nil {
		t.Fatal("unknown field accepted")
	}
}
