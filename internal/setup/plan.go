package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

// This file holds the decisions of the setup role that need no Windows API:
// command parsing, exit codes, the install-version decision, the Settings >
// Apps entry and the update journal (ADR-0010). The elevated steps that act
// on them are in the _windows files.

// Command is one setup action.
type Command string

// Setup commands (ADR-0010). None takes a path or a version.
const (
	CmdInstall     Command = "install"
	CmdRepair      Command = "repair"
	CmdApplyUpdate Command = "apply-update"
	CmdUninstall   Command = "uninstall"
)

// Invocation is a parsed setup command line.
type Invocation struct {
	Cmd   Command
	Purge bool // uninstall only
}

// ErrUsage is returned for any command line setup does not accept.
var ErrUsage = errors.New("usage: soireehost setup install | repair | apply-update | uninstall [--purge]")

// ParseArgs reads the arguments after "setup". Anything else, an extra
// argument included, is refused: setup acts only on fixed folders.
func ParseArgs(args []string) (Invocation, error) {
	switch {
	case len(args) == 1 && (args[0] == string(CmdInstall) || args[0] == string(CmdRepair) ||
		args[0] == string(CmdApplyUpdate) || args[0] == string(CmdUninstall)):
		return Invocation{Cmd: Command(args[0])}, nil
	case len(args) == 2 && args[0] == string(CmdUninstall) && args[1] == "--purge":
		return Invocation{Cmd: CmdUninstall, Purge: true}, nil
	}
	return Invocation{}, ErrUsage
}

// Code is setup's exit code: a closed set the control panel turns into a
// sentence from its message catalogue. Setup has no console when the
// Windows prompt starts it, so the code is how it reports.
type Code int

// Exit codes. Their numbers are part of the contract with the control
// panel; never renumber one.
const (
	CodeOK             Code = 0
	CodeFailed         Code = 1  // anything not listed; details in the event log
	CodeUsage          Code = 2  // a command line setup does not accept
	CodeNotElevated    Code = 10 // started without administrator rights
	CodeNotInstalled   Code = 11 // repair or apply-update from a copy that is not the installed one
	CodeBusy           Code = 12 // another setup is running
	CodeNewerInstalled Code = 13 // a newer version is already installed
	CodeUnsafeSource   Code = 14 // the program's folder can be changed by another account (DR-9)
	CodeNoUpdate       Code = 20 // nothing verified is staged
	CodeUpdateRefused  Code = 21 // the staged update failed a check (S-60 to S-63)
	CodeRolledBack     Code = 22 // the new version did not start; the previous one runs again
	CodeDataKept       Code = 30 // uninstalled, but a service did not stop, so the data folder was kept
)

// Error carries an exit code with the error that caused it.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// fail wraps err with code.
func fail(code Code, err error) error { return &Error{Code: code, Err: err} }

// ExitCode returns the exit code for setup's result.
func ExitCode(err error) Code {
	if err == nil {
		return CodeOK
	}
	if errors.Is(err, ErrUsage) {
		return CodeUsage
	}
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	return CodeFailed
}

// Codes lists every exit code, for the control panel's catalogue test.
func Codes() []Code {
	return []Code{CodeOK, CodeFailed, CodeUsage, CodeNotElevated, CodeNotInstalled, CodeBusy,
		CodeNewerInstalled, CodeUnsafeSource, CodeNoUpdate, CodeUpdateRefused, CodeRolledBack, CodeDataKept}
}

// installKind is what "setup install" does given the installed version.
type installKind int

const (
	installFresh   installKind = iota + 1 // nothing installed, or an install from before Phase 6 with no Apps entry
	installRepair                         // the same version
	installUpgrade                        // an older version
)

// decideInstall compares the installed version (from the Apps entry, empty
// when there is none) with this binary's. A newer installed version is
// refused, so no release runs settings written by a newer schema; the way
// back is uninstall, then install (ADR-0010).
func decideInstall(installed, mine string) (installKind, error) {
	if installed == "" || !version.Valid(installed) {
		return installFresh, nil
	}
	c, err := version.Compare(installed, mine)
	switch {
	case err != nil:
		return 0, fail(CodeFailed, fmt.Errorf("this program's version %q is not valid", mine))
	case c == 0:
		return installRepair, nil
	case c < 0:
		return installUpgrade, nil
	}
	return 0, fail(CodeNewerInstalled, fmt.Errorf("a newer SoiréeHost (%s) is already installed; uninstall it first to install %s", installed, mine))
}

// UninstallKey is the Settings > Apps entry, under HKLM in the 64-bit view.
const UninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SoireeHost`

// regValue is one value of the Apps entry: a string, or a DWORD when
// IsDword is set.
type regValue struct {
	Name    string
	Text    string
	Dword   uint32
	IsDword bool
}

// appsEntry lists the values of the Apps entry (ADR-0010). Publisher names
// the project, never a person.
func appsEntry(l Layout, ver string, sizeKB uint32) []regValue {
	exe := l.Exe()
	return []regValue{
		{Name: "DisplayName", Text: "SoiréeHost"},
		{Name: "DisplayVersion", Text: ver},
		{Name: "Publisher", Text: "SoiréeHost project"},
		{Name: "DisplayIcon", Text: quote(exe) + ",0"},
		{Name: "InstallLocation", Text: l.ProgramDir},
		{Name: "UninstallString", Text: quote(exe) + " gui --uninstall"},
		{Name: "URLInfoAbout", Text: "https://github.com/TheAlsaadi/SoireeHost"},
		{Name: "NoModify", Dword: 1, IsDword: true},
		{Name: "NoRepair", Dword: 1, IsDword: true},
		{Name: "EstimatedSize", Dword: sizeKB, IsDword: true},
	}
}

func quote(p string) string { return `"` + p + `"` }

// Update journal (ADR-0010). apply-update writes it before each step, so an
// interrupted update can be finished or undone by the next setup command.

// Step is how far an update got.
type Step string

// Steps, in order.
const (
	StepVerified    Step = "verified"     // checks passed; nothing changed yet
	StepStaged      Step = "staged"       // soireehost.exe.new written and checked
	StepStopped     Step = "stopped"      // services stopped
	StepSnapshot    Step = "snapshot"     // config copied aside, after the stop
	StepSwapped     Step = "swapped"      // binaries renamed: the new one is in place
	StepFinished    Step = "finished"     // the new version's repair ran; waiting for its supervisor
	StepRollingBack Step = "rolling_back" // putting the previous version back
)

var steps = []Step{StepVerified, StepStaged, StepStopped, StepSnapshot, StepSwapped, StepFinished, StepRollingBack}

// Journal is the content of update.json.
type Journal struct {
	From    string    `json:"from"`
	To      string    `json:"to"`
	Step    Step      `json:"step"`
	OldHash string    `json:"old_sha256"`
	NewHash string    `json:"new_sha256"`
	Started time.Time `json:"started"`
	// PID is the apply-update process that wrote the journal. The new
	// version's repair, which that process starts while it holds the setup
	// lock, may run only as its child (ADR-0010).
	PID int `json:"pid"`
}

// maxJournal bounds update.json.
const maxJournal = 4 << 10

// Encode writes the journal.
func (j Journal) Encode() ([]byte, error) { return json.Marshal(j) }

// DecodeJournal reads update.json strictly. The file lives in the program
// folder, which only administrators can write, but it is still checked:
// a damaged journal must lead to the safe action, not a guess.
func DecodeJournal(b []byte) (Journal, error) {
	if len(b) > maxJournal {
		return Journal{}, errors.New("update journal is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j Journal
	if err := dec.Decode(&j); err != nil {
		return Journal{}, fmt.Errorf("update journal: %w", err)
	}
	if dec.More() {
		return Journal{}, errors.New("update journal: data after the object")
	}
	switch {
	case !version.Valid(j.From), !version.Valid(j.To):
		return Journal{}, errors.New("update journal: invalid version")
	case !validStep(j.Step):
		return Journal{}, errors.New("update journal: unknown step")
	case !hexHash(j.OldHash), !hexHash(j.NewHash):
		return Journal{}, errors.New("update journal: invalid hash")
	case j.PID <= 0:
		return Journal{}, errors.New("update journal: invalid process id")
	}
	return j, nil
}

func validStep(s Step) bool { return slices.Contains(steps, s) }

func hexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Recovery is what to do with an interrupted update.
type Recovery int

// Recoveries.
const (
	// RecoverCleanup: the binaries were never swapped. Remove the
	// leftovers and make sure the installed version runs.
	RecoverCleanup Recovery = iota + 1
	// RecoverConfirm: the new version finished its own repair. If its
	// supervisor answers with the new version, the update is done;
	// otherwise roll back.
	RecoverConfirm
	// RecoverRollback: put the previous binaries and config back.
	RecoverRollback
)

// Decide picks the recovery for an interrupted update. installedHash is the
// SHA-256 of the soireehost.exe now in the program folder ("" if it is
// missing). The new version is never trusted to have finished unless the
// journal says so and the installed file is the new one; anything after
// the swap that is not clearly finished is rolled back, since the previous
// version was known to run. The staged update stays in the updates folder,
// so the user can try Install again.
func Decide(j Journal, installedHash string) Recovery {
	switch j.Step {
	case StepVerified, StepStaged, StepStopped, StepSnapshot:
		return RecoverCleanup
	case StepFinished:
		if installedHash == j.NewHash {
			return RecoverConfirm
		}
	}
	return RecoverRollback
}

// Program folder files that apply-update uses (ADR-0010).
const (
	journalName = supervisor.UpdateJournalName
	rollbackDir = "rollback"
)

// JournalPath is the journal in the program folder.
func (l Layout) JournalPath() string { return filepath.Join(l.ProgramDir, journalName) }

// RollbackDir holds the config snapshot during an update.
func (l Layout) RollbackDir() string { return filepath.Join(l.ProgramDir, rollbackDir) }

// rollbackResult is CodeRolledBack only when the previous version was put
// back and started; a rollback that failed itself is reported as a plain
// failure, so the control panel never says the previous version runs when
// it may not.
func rollbackResult(to string, cause error, restoreErrs []error) error {
	if len(restoreErrs) > 0 {
		return fail(CodeFailed, fmt.Errorf("the update to %s failed (%w), and putting the previous version back failed too: %w; run Repair",
			to, cause, errors.Join(restoreErrs...)))
	}
	return fail(CodeRolledBack, fmt.Errorf("the update to %s was rolled back: %w", to, cause))
}

// EventSource is setup's own Application event log source (ADR-0010).
const EventSource = "SoireeHost Setup"

// Event kinds for Report.
const (
	eventInfo = iota + 1
	eventWarning
	eventError
)

// eventFor is what Report writes for a setup result: success is
// information, a rolled-back update a warning tagged update.rollback, and
// every other failure an error. The event id is the exit code (1 for
// success), within the 1 to 1000 range the EventCreate message file covers.
func eventFor(cmd Command, err error) (kind int, id uint32, text string) {
	code := ExitCode(err)
	switch {
	case err == nil:
		return eventInfo, 1, fmt.Sprintf("setup %s finished; SoiréeHost %s.", cmd, version.Current())
	case code == CodeRolledBack:
		return eventWarning, uint32(code), fmt.Sprintf("update.rollback: setup %s exited with code %d: %v", cmd, code, err) // #nosec G115 -- a small exit code
	}
	return eventError, uint32(code), fmt.Sprintf("setup %s failed with code %d: %v", cmd, code, err) // #nosec G115 -- a small exit code
}

// signatureAllows is the S-61 rule for an update (ADR-0004): while the
// running program is unsigned, the signed manifest (S-60) is the only proof
// of origin and any candidate may follow; once the running program carries
// a valid Authenticode signature, the candidate must carry one too, from
// the same publisher, so an update never moves from signed to unsigned.
// A signed program whose own signature does not verify here, or whose
// publisher cannot be read, refuses every update: a check that cannot run
// never counts as "unsigned" (insecure-defaults audit of 20 Nov 2026).
func signatureAllows(runSigned, runValid bool, runPublisher string, newValid bool, newPublisher string) error {
	switch {
	case runSigned && !runValid:
		return fail(CodeUpdateRefused, errors.New("this program is signed, but its own signature does not verify on this PC, so the update cannot be checked against it (S-61); run Repair or reinstall"))
	case !runValid:
		return nil
	case runPublisher == "":
		return fail(CodeUpdateRefused, errors.New("this program is signed, but its publisher could not be read"))
	case !newValid:
		return fail(CodeUpdateRefused, errors.New("the update is not validly signed, and this version is; SoiréeHost never moves from signed to unsigned (S-61)"))
	case newPublisher != runPublisher:
		return fail(CodeUpdateRefused, fmt.Errorf("the update is signed by %q, not by %q", newPublisher, runPublisher))
	}
	return nil
}

// keepStopped makes sure the services are still stopped, stopping them again
// if they are not. The service manager may start the supervisor again on its
// own while an update has it stopped: a recovery action scheduled by an
// earlier failure (5, 30 or 60 seconds later) fires on its timer whatever
// setup is doing. Before the swap such a supervisor runs the old program;
// left alone it keeps serving the control pipe through the new version's
// repair, and the version check then rolls the update back for nothing.
// running reports whether any service is not stopped (true when it cannot
// tell); stop stops them all and waits for their processes.
func keepStopped(running, stop func() bool) bool {
	for range 3 {
		if !running() {
			return true
		}
		if !stop() {
			return false
		}
	}
	return !running()
}
