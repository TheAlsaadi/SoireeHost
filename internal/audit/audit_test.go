package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec/winsectest"
)

// memAnchor is an AnchorStore in memory; loadErr and saveErr inject failures.
type memAnchor struct {
	a       Anchor
	set     bool
	loadErr error
	saveErr error
}

func (m *memAnchor) LoadAnchor() (Anchor, bool, error) { return m.a, m.set, m.loadErr }
func (m *memAnchor) SaveAnchor(a Anchor) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.a, m.set = a, true
	return nil
}

var user = mustSID("S-1-5-21-1")

func mustSID(s string) Actor {
	a, err := SID(s)
	if err != nil {
		panic(err)
	}
	return a
}

func newLog(t *testing.T) (*Log, string, *memAnchor) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.log")
	m := &memAnchor{}
	l, rep, err := Open(p, m)
	if err != nil || !rep.OK() {
		t.Fatalf("open: %v %+v", err, rep)
	}
	n := 0
	l.now = func() time.Time { n++; return time.Date(2026, 11, 12, 10, 0, n, 0, time.UTC) }
	return l, p, m
}

func fill(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Append(user, SitePut, map[string]string{"site": "blog", "i": string(rune('a' + i))}); err != nil {
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

// verifyChainOnly is the chain check without an anchor: what the log could
// tell before SE-13.
func verifyChainOnly(t *testing.T, p string) Report {
	t.Helper()
	rep, _, err := verifyFile(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// mustBreakAtOpen reopens the log and wants ErrBroken with a usable Log.
func mustBreakAtOpen(t *testing.T, p string, m *memAnchor) *Log {
	t.Helper()
	l, rep, err := Open(p, m)
	if !errors.Is(err, ErrBroken) || rep.OK() || l == nil {
		t.Fatalf("open on a broken log: %v, %+v, log %v", err, rep, l != nil)
	}
	return l
}

func TestChainVerifies(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 5)
	rep, err := l.Verify()
	if err != nil || !rep.OK() || rep.Entries != 5 {
		t.Fatalf("report %+v, %v", rep, err)
	}
	if m.a.Seq != 5 {
		t.Fatalf("anchor %+v", m.a)
	}
	// reopening continues the chain
	l2, rep, err := Open(p, m)
	if err != nil || !rep.OK() {
		t.Fatal(err, rep)
	}
	if e, err := l2.Append(System, ConfigRollback, nil); err != nil || e.Seq != 6 {
		t.Fatalf("seq %d, %v", e.Seq, err)
	}
	if rep, _ := l2.Verify(); !rep.OK() || rep.Entries != 6 {
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
		"edited last entry": func(ls [][]byte) [][]byte {
			ls[4] = bytes.Replace(ls[4], []byte(`"site":"blog"`), []byte(`"site":"evil"`), 1)
			return ls
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l, p, m := newLog(t)
			fill(t, l, 5)
			write(t, p, mutate(lines(t, p)))
			rep, err := l.Verify()
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK() {
				t.Fatal("tampering not detected")
			}
			mustBreakAtOpen(t, p, m)
		})
	}
}

// SE-13: cutting entries off the end still chains from the genesis, so only
// the anchor shows it; the break stays reported after later appends.
func TestTruncationDetected(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 5)
	write(t, p, lines(t, p)[:3])
	if rep := verifyChainOnly(t, p); !rep.OK() {
		t.Fatalf("the cut file should chain by itself: %+v", rep)
	}
	if rep, _ := l.Verify(); rep.OK() {
		t.Fatal("truncation not detected")
	}
	l2 := mustBreakAtOpen(t, p, m)
	e, err := l2.Append(System, SupervisorStart, nil)
	if err != nil || e.Seq != 6 {
		t.Fatalf("append after truncation: seq %d, %v", e.Seq, err)
	}
	// the anchor now names the new entry, but the file keeps the gap
	mustBreakAtOpen(t, p, m)
}

// SE-13: a deleted file is reported, and stays reported once a new file is
// started.
func TestDeletionDetected(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 3)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if rep, err := l.Verify(); err != nil || rep.OK() {
		t.Fatalf("deletion not detected: %+v %v", rep, err)
	}
	l2 := mustBreakAtOpen(t, p, m)
	if e, err := l2.Append(System, SupervisorStart, nil); err != nil || e.Seq != 4 {
		t.Fatalf("append after deletion: seq %d, %v", e.Seq, err)
	}
	mustBreakAtOpen(t, p, m)
}

// SE-13: rewriting every entry and recomputing every hash makes a chain that
// verifies by itself; the anchor still holds the real newest hash.
func TestRehashDetected(t *testing.T) {
	for _, extra := range []int{0, 2} {
		l, p, m := newLog(t)
		fill(t, l, 5)
		prev := genesis
		var out [][]byte
		for i := range 5 + extra {
			e := Entry{Seq: uint64(i + 1), Time: time.Date(2026, 11, 12, 10, 0, i, 0, time.UTC),
				Actor: "S-1-5-21-9", Action: "site.put", Detail: map[string]string{"site": "forged"}, Prev: prev}
			h, err := hashOf(e)
			if err != nil {
				t.Fatal(err)
			}
			e.Hash, prev = h, h
			b, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b)
		}
		write(t, p, out)
		if rep := verifyChainOnly(t, p); !rep.OK() {
			t.Fatalf("the forged chain should verify by itself: %+v", rep)
		}
		if rep, _ := l.Verify(); rep.OK() {
			t.Fatalf("rehash with %d extra entries not detected", extra)
		}
		l2 := mustBreakAtOpen(t, p, m)
		if _, err := l2.Append(System, SupervisorStart, nil); err != nil {
			t.Fatal(err)
		}
		mustBreakAtOpen(t, p, m)
	}
}

// SE-13: Open returns ErrBroken, the report and a Log that still appends.
func TestOpenReportsBrokenChain(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 4)
	ls := lines(t, p)
	write(t, p, append(ls[:1], ls[2:]...))
	l2, rep, err := Open(p, m)
	if !errors.Is(err, ErrBroken) || len(rep.Breaks) == 0 || l2 == nil {
		t.Fatalf("open: %v %+v", err, rep)
	}
	if _, err := l2.Append(System, SupervisorStart, nil); err != nil {
		t.Fatalf("append on a broken log: %v", err)
	}
	if _, _, err := Open(p, nil); err == nil || errors.Is(err, ErrBroken) {
		t.Fatalf("open without an anchor store: %v", err)
	}
}

// A log written before anchors existed opens cleanly, gains an
// audit.anchored entry, and is protected from then on.
func TestMissingAnchorMigrates(t *testing.T) {
	l, p, _ := newLog(t)
	fill(t, l, 3)
	fresh := &memAnchor{}
	l2, rep, err := Open(p, fresh)
	if err != nil || !rep.OK() {
		t.Fatalf("open old log: %v %+v", err, rep)
	}
	all, err := List(p, 0, 10)
	if err != nil || len(all) != 4 || all[3].Action != "audit.anchored" || all[3].Detail["reason"] != "missing" || all[3].Actor != System.String() {
		t.Fatalf("entries %+v %v", all, err)
	}
	if fresh.a.Seq != 4 {
		t.Fatalf("anchor %+v", fresh.a)
	}
	fill(t, l2, 1)
	write(t, p, lines(t, p)[:4])
	mustBreakAtOpen(t, p, fresh)
}

// An anchor that cannot be read is a break; the log is anchored again and
// says so in an entry.
func TestUnreadableAnchor(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 2)
	m.loadErr = errors.New("cannot decrypt")
	if rep, _ := l.Verify(); rep.OK() {
		t.Fatal("unreadable anchor not reported by Verify")
	}
	l2 := mustBreakAtOpen(t, p, m)
	m.loadErr = nil
	if m.a.Seq != 3 {
		t.Fatalf("anchor %+v", m.a)
	}
	all, _ := List(p, 2, 10)
	if len(all) != 1 || all[0].Detail["reason"] != "unreadable" {
		t.Fatalf("entries %+v", all)
	}
	if rep, _ := l2.Verify(); !rep.OK() {
		t.Fatalf("after re-anchoring %+v", rep)
	}
}

// A failure to save the anchor fails the append, so callers treat the
// entry as not written (S-32).
func TestAnchorSaveFailureReported(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 1)
	m.saveErr = errors.New("disk full")
	if _, err := l.Append(user, SitePut, nil); err == nil {
		t.Fatal("append succeeded without saving the anchor")
	}
	// nothing was written: the entry cannot claim a change that was refused
	if n := len(lines(t, p)); n != 1 {
		t.Fatalf("%d lines after a refused append", n)
	}
	m.saveErr = nil
	if rep, _ := l.Verify(); !rep.OK() {
		t.Fatalf("report %+v", rep)
	}
}

// The anchor is saved before each write, so an entry that never reached the
// file (a crash, a power loss) is reported, and stays reported.
func TestEntryLostAfterAnchorSaved(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 3)
	m.a = Anchor{Seq: 4, Hash: strings.Repeat("ab", 32)}
	l2 := mustBreakAtOpen(t, p, m)
	if e, err := l2.Append(System, SupervisorStart, nil); err != nil || e.Seq != 5 {
		t.Fatalf("append: seq %d %v", e.Seq, err)
	}
	mustBreakAtOpen(t, p, m)
}

// Review of SE-13: a correctly chained entry added to the file by someone
// other than the supervisor is past the anchor and reported, and stays
// reported after a restart and further appends.
func TestEntriesAddedAfterAnchor(t *testing.T) {
	for _, n := range []int{1, 3} {
		l, p, m := newLog(t)
		fill(t, l, 3)
		ls := lines(t, p)
		var last Entry
		if err := json.Unmarshal(ls[len(ls)-1], &last); err != nil {
			t.Fatal(err)
		}
		for i := range n {
			e := Entry{Seq: last.Seq + 1, Time: last.Time.Add(time.Second), Actor: "S-1-5-21-9", Action: "site.remove",
				Detail: map[string]string{"site": "forged", "i": string(rune('a' + i))}, Prev: last.Hash}
			h, err := hashOf(e)
			if err != nil {
				t.Fatal(err)
			}
			e.Hash = h
			b, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			ls = append(ls, b)
			last = e
		}
		write(t, p, ls)
		if rep := verifyChainOnly(t, p); !rep.OK() {
			t.Fatalf("the forged entries should chain by themselves: %+v", rep)
		}
		if rep, _ := l.Verify(); rep.OK() {
			t.Fatalf("%d added entries not detected", n)
		}
		l2 := mustBreakAtOpen(t, p, m)
		if _, err := l2.Append(System, SupervisorStart, nil); err != nil {
			t.Fatal(err)
		}
		mustBreakAtOpen(t, p, m)
	}
}

// Open does not fail when it cannot save the first anchor: that is a break.
func TestOpenWithoutSavableAnchor(t *testing.T) {
	m := &memAnchor{saveErr: errors.New("disk full")}
	l, rep, err := Open(filepath.Join(t.TempDir(), "audit.log"), m)
	if !errors.Is(err, ErrBroken) || rep.OK() || l == nil {
		t.Fatalf("open: %v %+v", err, rep)
	}
}

// SE-15: detail keys that name secrets are refused, as are keys that are
// not plain names and too many keys; nothing is written.
func TestSecretLikeKeysRefused(t *testing.T) {
	l, p, _ := newLog(t)
	for _, k := range []string{"token", "tunnel_token", "password", "passwd", "pwd", "secret", "client_secret",
		"key", "api_key", "credential", "creds", "cookie", "auth", "authorization", "bearer", "private_key", "signature"} {
		if _, err := l.Append(user, SecretSet, map[string]string{k: "x"}); !errors.Is(err, ErrSecretKey) {
			t.Errorf("key %q: %v", k, err)
		}
	}
	for _, k := range []string{"", "Site", "site name", "a-b", strings.Repeat("a", 33), "1site"} {
		if _, err := l.Append(user, SitePut, map[string]string{k: "x"}); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
	many := map[string]string{}
	for i := range MaxDetailKeys + 1 {
		many["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "x"
	}
	if _, err := l.Append(user, SitePut, many); err == nil {
		t.Error("too many keys accepted")
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused entry reached the file: %v", err)
	}
	// every key the supervisor uses is accepted
	ok := map[string]string{}
	for _, k := range []string{"site", "type", "root", "target", "revision", "weakening", "exposed", "to_revision",
		"name", "enabled", "port", "offline", "sites", "check", "role", "restarts", "delay", "version", "audit_ok",
		"action", "new_revision", "failed_revision", "restored_revision", "cause", "reason", "from_seq"} {
		ok[k] = "x"
	}
	if _, err := l.Append(user, SitePut, ok); err != nil {
		t.Fatalf("supervisor keys refused: %v", err)
	}
}

// SE-15: actors are SIDs, actions come from the closed set.
func TestTypedAPI(t *testing.T) {
	if System.String() != winsec.SIDSystem {
		t.Fatalf("System is %s", System)
	}
	for _, s := range []string{"S-1-5-18", "S-1-5-21-1-2-3-1001", "S-1-5-80-1-2-3-4-5"} {
		if a, err := SID(s); err != nil || a.String() != s {
			t.Errorf("SID(%q): %v", s, err)
		}
	}
	for _, s := range []string{"", "site.put", "S-1", "S-1-5-", "s-1-5-18", "S-1-5-18 ", "S-1-5-18\n", "Administrator"} {
		if _, err := SID(s); err == nil {
			t.Errorf("SID(%q) accepted", s)
		}
	}
	l, _, _ := newLog(t)
	if _, err := l.Append(Actor{}, SitePut, nil); err == nil {
		t.Error("zero actor accepted")
	}
	for _, a := range []Action{actionInvalid, actionEnd, Action(200)} {
		if _, err := l.Append(user, a, nil); err == nil {
			t.Errorf("action %d accepted", a)
		}
	}
	seen := map[string]bool{}
	for a := actionInvalid + 1; a < actionEnd; a++ {
		n := a.String()
		if n == "" || seen[n] || strings.ContainsAny(n, " \t") {
			t.Errorf("action %d has name %q", a, n)
		}
		seen[n] = true
	}
	e, err := l.Append(user, SecretReplaceFailed, nil)
	if err != nil || e.Action != "secret.replace.failed" || e.Actor != "S-1-5-21-1" {
		t.Fatalf("entry %+v %v", e, err)
	}
}

// A crash that leaves a partial last line is reported once, and later
// entries still chain and verify.
func TestPartialLineThenAppend(t *testing.T) {
	l, p, m := newLog(t)
	fill(t, l, 3)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":4,"ti`)
	_ = f.Close()
	l2, rep, err := Open(p, m)
	if !errors.Is(err, ErrBroken) || len(rep.Breaks) != 1 {
		t.Fatalf("open report %+v, %v", rep, err)
	}
	if e, err := l2.Append(System, SupervisorStart, nil); err != nil || e.Seq != 4 {
		t.Fatalf("append after partial line: %+v %v", e, err)
	}
	rep, _ = l2.Verify()
	if len(rep.Breaks) != 1 || rep.Entries != 4 {
		t.Fatalf("report %+v", rep)
	}
}

func TestList(t *testing.T) {
	l, p, _ := newLog(t)
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
	l, _, _ := newLog(t)
	if _, err := l.Append(user, SitePut, map[string]string{"x": strings.Repeat("y", MaxLineBytes)}); err == nil {
		t.Fatal("oversized entry written")
	}
}

// CI regression: appending works more than once under the installed audit
// folder's append-only permissions (winsec.AuditFolderSDDL), and the
// supervisor still cannot rewrite the file.
func TestAppendUnderAppendOnlyFolder(t *testing.T) {
	c, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "audit")
	// The extra folder-only entry lets the test's cleanup delete the file (the
	// real folder grants no one that); it does not reach the file itself.
	if err := winsectest.SetFolderSDDL(dir, "O:"+c.SID+winsec.AuditFolderSDDL(c.SID)+"(A;;FA;;;"+c.SID+")"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "audit.log")
	l, _, err := Open(p, &memAnchor{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := l.Append(System, SupervisorStart, nil); err != nil {
			t.Fatalf("append %d: %v", i+1, err)
		}
	}
	if rep, err := l.Verify(); err != nil || !rep.OK() || rep.Entries != 3 {
		t.Fatalf("report %+v %v", rep, err)
	}
	if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil { //nolint:gosec // G304: the test's own file
		_ = f.Close()
		t.Fatal("the audit file can be opened for overwriting")
	}
}
