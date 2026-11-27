package supervisor

import (
	"os"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// UpdateJournalName is apply-update's journal in the program folder
// (ADR-0010); setup writes it and the supervisor only looks for it.
const UpdateJournalName = "update.json"

// updateStalled is how long a journal must stay unchanged before status
// calls the update interrupted: longer than apply-update waits for the new
// version's repair (5 minutes) and its supervisor's answer (90 seconds), so
// an update still running is never reported as stopped.
const updateStalled = 10 * time.Minute

// statusUpdate is the update part of status: an interrupted update first,
// since it needs Repair before anything else.
func (s *Supervisor) statusUpdate() ipc.UpdateStatus {
	switch {
	case s.updateInterrupted():
		return ipc.UpdateStatus{State: ipc.UpdateInterrupted}
	case s.upd != nil:
		return s.upd.status()
	default:
		return ipc.UpdateStatus{State: ipc.UpdateOff}
	}
}

// updateInterrupted reports whether an update stopped part way: its journal
// is still in the program folder and has not changed for updateStalled.
// Repair then finishes or undoes it (S-63, owner's decision of 27 Nov 2026).
func (s *Supervisor) updateInterrupted() bool {
	if s.opts.UpdateJournal == "" {
		return false
	}
	fi, err := os.Lstat(s.opts.UpdateJournal)
	return err == nil && time.Since(fi.ModTime()) > updateStalled
}
