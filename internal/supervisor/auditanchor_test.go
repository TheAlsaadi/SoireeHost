package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
)

// newBare is a supervisor that is never run: enough to open its stores.
func newBare(t *testing.T, root string) *Supervisor {
	t.Helper()
	p := Paths{Root: root}
	for _, d := range []string{p.Config(), p.Secrets(), p.Audit()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Options{SkipACLCheck: true, Paths: p})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// SE-13: the anchor lives in the DPAPI secrets store, and a deleted or cut
// audit log is reported at start (audit_ok false) without stopping the
// supervisor.
func TestAuditAnchorInSecretsStore(t *testing.T) {
	root := filepath.Join(dataRoot, "anchor-"+randHex())
	s := newBare(t, root)
	if !s.auditOK() {
		t.Fatal("new log not OK")
	}
	for range 3 {
		if err := s.record(audit.System, audit.SupervisorStart, map[string]string{"version": "test"}); err != nil {
			t.Fatal(err)
		}
	}
	a, ok, err := secretAnchor{s.secrets}.LoadAnchor()
	if err != nil || !ok || a.Seq != 3 {
		t.Fatalf("anchor %+v %v %v", a, ok, err)
	}
	if st, err := s.secrets.Status(auditAnchorName); err != nil || !st.Set {
		t.Fatalf("anchor not in the secrets store: %+v %v", st, err)
	}
	log := filepath.Join(s.opts.Paths.Audit(), "audit.log")
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}
	s2 := newBare(t, root)
	if s2.auditOK() {
		t.Fatal("deleted audit log not reported at start")
	}
	if rep, err := s2.audit.Verify(); err != nil || rep.OK() {
		t.Fatalf("audit.list check: %+v %v", rep, err)
	}
	// a damaged anchor is reported too, and the supervisor still starts
	if err := s2.secrets.Set(auditAnchorName, []byte(`{"seq":1,"hash":"x","extra":1}`)); err != nil {
		t.Fatal(err)
	}
	if s3 := newBare(t, root); s3.auditOK() {
		t.Fatal("damaged anchor not reported")
	}
}

// SE-15: a caller whose SID is not shaped like one cannot be audited, so a
// weakening change by it is refused.
func TestActorOf(t *testing.T) {
	if actorOf("S-1-5-21-1-2-3-1001").String() != "S-1-5-21-1-2-3-1001" {
		t.Fatal("valid SID lost")
	}
	s := newBare(t, filepath.Join(dataRoot, "actor-"+randHex()))
	if err := s.record(actorOf("not a sid"), audit.SitePut, nil); err == nil {
		t.Fatal("entry written for a malformed actor")
	}
}
