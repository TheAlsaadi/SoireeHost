package supervisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// S-63 (owner's decision of 27 Nov 2026): a journal left in the program
// folder means an update stopped part way, and status says so; one still
// being written by a running update does not.
func TestInterruptedUpdateIsReported(t *testing.T) {
	journal := filepath.Join(t.TempDir(), UpdateJournalName)
	s := &Supervisor{opts: Options{UpdateJournal: journal}}
	if s.updateInterrupted() {
		t.Fatal("no journal, but the update is reported interrupted")
	}
	if err := os.WriteFile(journal, []byte(`{"step":"swapped"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s.updateInterrupted() {
		t.Fatal("a journal an update is still writing is reported interrupted")
	}
	old := time.Now().Add(-updateStalled - time.Minute)
	if err := os.Chtimes(journal, old, old); err != nil {
		t.Fatal(err)
	}
	if !s.updateInterrupted() {
		t.Fatal("a stalled journal is not reported")
	}
	if st := s.statusUpdate(); st.State != "interrupted" {
		t.Fatalf("status reports %q, want interrupted", st.State)
	}
	if (&Supervisor{}).updateInterrupted() {
		t.Fatal("no journal path set, but the update is reported interrupted")
	}
}
