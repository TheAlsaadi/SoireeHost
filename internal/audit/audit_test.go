package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newLog(t *testing.T) (*Log, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.log")
	l, rep, err := Open(p)
	if err != nil || !rep.OK() {
		t.Fatalf("open: %v %+v", err, rep)
	}
	n := 0
	l.now = func() time.Time { n++; return time.Date(2026, 11, 12, 10, 0, n, 0, time.UTC) }
	return l, p
}

func fill(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Append("S-1-5-21-1", "site.put", map[string]string{"site": "blog", "i": string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
}

func lines(t *testing.T, p string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func write(t *testing.T, p string, ls [][]byte) {
	t.Helper()
	if err := os.WriteFile(p, append(bytes.Join(ls, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifies(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 5)
	rep, err := Verify(p)
	if err != nil || !rep.OK() || rep.Entries != 5 {
		t.Fatalf("report %+v, %v", rep, err)
	}
	// reopening continues the chain
	l2, rep, err := Open(p)
	if err != nil || !rep.OK() {
		t.Fatal(err, rep)
	}
	if e, err := l2.Append("S-1-5-18", "config.rollback", nil); err != nil || e.Seq != 6 {
		t.Fatalf("seq %d, %v", e.Seq, err)
	}
	if rep, _ := Verify(p); !rep.OK() || rep.Entries != 6 {
		t.Fatalf("after reopen %+v", rep)
	}
}

// S-36: each kind of tampering is detected.
func TestTamperingDetected(t *testing.T) {
	cases := map[string]func([][]byte) [][]byte{
		"edited detail": func(ls [][]byte) [][]byte {
			ls[2] = bytes.Replace(ls[2], []byte(`"site":"blog"`), []byte(`"site":"evil"`), 1)
			return ls
		},
		"edited actor and rehashed is still caught by the next link": func(ls [][]byte) [][]byte {
			ls[1] = bytes.Replace(ls[1], []byte("S-1-5-21-1"), []byte("S-1-5-21-2"), 1)
			return ls
		},
		"removed entry": func(ls [][]byte) [][]byte { return append(ls[:2], ls[3:]...) },
		"reordered":     func(ls [][]byte) [][]byte { ls[1], ls[2] = ls[2], ls[1]; return ls },
		"duplicated":    func(ls [][]byte) [][]byte { return append(ls[:3], append([][]byte{ls[2]}, ls[3:]...)...) },
		"garbage line":  func(ls [][]byte) [][]byte { return append(ls, []byte("{not json")) },
		"unknown field": func(ls [][]byte) [][]byte {
			ls[0] = bytes.Replace(ls[0], []byte(`{"seq"`), []byte(`{"x":1,"seq"`), 1)
			return ls
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l, p := newLog(t)
			fill(t, l, 5)
			write(t, p, mutate(lines(t, p)))
			rep, err := Verify(p)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK() {
				t.Fatal("tampering not detected")
			}
		})
	}
}

// A crash that leaves a partial last line is reported once, and later
// entries still chain and verify.
func TestPartialLineThenAppend(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 3)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":4,"ti`)
	_ = f.Close()
	l2, rep, err := Open(p)
	if err != nil || len(rep.Breaks) != 1 {
		t.Fatalf("open report %+v, %v", rep, err)
	}
	if e, err := l2.Append("S-1-5-18", "x", nil); err != nil || e.Seq != 4 {
		t.Fatalf("append after partial line: %+v %v", e, err)
	}
	rep, _ = Verify(p)
	if len(rep.Breaks) != 1 || rep.Entries != 4 {
		t.Fatalf("report %+v", rep)
	}
}

func TestList(t *testing.T) {
	l, p := newLog(t)
	fill(t, l, 5)
	got, err := List(p, 2, 2)
	if err != nil || len(got) != 2 || got[0].Seq != 3 || got[1].Seq != 4 {
		t.Fatalf("list %+v, %v", got, err)
	}
	if got, err := List(filepath.Join(t.TempDir(), "none"), 0, 10); err != nil || got != nil {
		t.Fatalf("missing log: %v %v", got, err)
	}
}

func TestOversizedEntryRefused(t *testing.T) {
	l, _ := newLog(t)
	if _, err := l.Append("a", "b", map[string]string{"x": strings.Repeat("y", MaxLineBytes)}); err == nil {
		t.Fatal("oversized entry written")
	}
}
