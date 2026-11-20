package setup

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	good := map[string]Invocation{
		"install":           {Cmd: CmdInstall},
		"repair":            {Cmd: CmdRepair},
		"apply-update":      {Cmd: CmdApplyUpdate},
		"uninstall":         {Cmd: CmdUninstall},
		"uninstall --purge": {Cmd: CmdUninstall, Purge: true},
	}
	for line, want := range good {
		got, err := ParseArgs(strings.Fields(line))
		if err != nil || got != want {
			t.Errorf("ParseArgs(%q) = %+v, %v", line, got, err)
		}
	}
	// no command takes a path, a version or any extra argument (ADR-0010)
	for _, line := range []string{
		"", "Install", "install --purge", "repair now", "apply-update C:\\Users\\x\\Downloads\\soireehost.exe",
		"apply-update 1.3.0", "uninstall --purge extra", "uninstall --PURGE", "uninstall -purge", "--purge uninstall",
	} {
		if _, err := ParseArgs(strings.Fields(line)); !errors.Is(err, ErrUsage) {
			t.Errorf("ParseArgs(%q) accepted", line)
		}
	}
}

func TestExitCodes(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes() {
		if seen[c] {
			t.Fatalf("code %d listed twice", c)
		}
		seen[c] = true
	}
	for err, want := range map[error]Code{
		nil:                             CodeOK,
		ErrUsage:                        CodeUsage,
		errors.New("disk full"):         CodeFailed,
		fail(CodeBusy, errors.New("x")): CodeBusy,
		fmt.Errorf("wrapped: %w", fail(CodeRolledBack, errors.New("y"))): CodeRolledBack,
	} {
		if got := ExitCode(err); got != want {
			t.Errorf("ExitCode(%v) = %d, want %d", err, got, want)
		}
	}
	// the numbers are a contract with the control panel
	for c, n := range map[Code]int{CodeNotElevated: 10, CodeNewerInstalled: 13, CodeUpdateRefused: 21, CodeRolledBack: 22, CodeDataKept: 30} {
		if int(c) != n {
			t.Errorf("code renumbered: %d is now %d", n, c)
		}
	}
}

func TestDecideInstall(t *testing.T) {
	for _, tt := range []struct {
		installed, mine string
		want            installKind
		code            Code
	}{
		{"", "1.3.0", installFresh, 0},
		{"garbage", "1.3.0", installFresh, 0},
		{"1.3.0", "1.3.0", installRepair, 0},
		{"1.2.0", "1.3.0", installUpgrade, 0},
		{"1.3.0-rc.1", "1.3.0", installUpgrade, 0},
		{"1.4.0", "1.3.0", 0, CodeNewerInstalled},
		{"1.3.0", "1.3.0-rc.1", 0, CodeNewerInstalled},
	} {
		got, err := decideInstall(tt.installed, tt.mine)
		if tt.code != 0 {
			if ExitCode(err) != tt.code {
				t.Errorf("installed %q, mine %q: error %v, want code %d", tt.installed, tt.mine, err, tt.code)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("installed %q, mine %q: %v, %v; want %v", tt.installed, tt.mine, got, err, tt.want)
		}
	}
}

func TestAppsEntry(t *testing.T) {
	l := Layout{ProgramDir: `C:\Program Files\SoireeHost`, DataRoot: `C:\ProgramData\SoireeHost`}
	vals := map[string]regValue{}
	for _, v := range appsEntry(l, "1.3.0", 98765) {
		if _, dup := vals[v.Name]; dup {
			t.Fatalf("value %s set twice", v.Name)
		}
		vals[v.Name] = v
	}
	for name, want := range map[string]string{
		"DisplayName":     "SoiréeHost",
		"DisplayVersion":  "1.3.0",
		"Publisher":       "SoiréeHost project",
		"DisplayIcon":     `"C:\Program Files\SoireeHost\soireehost.exe",0`,
		"InstallLocation": `C:\Program Files\SoireeHost`,
		"UninstallString": `"C:\Program Files\SoireeHost\soireehost.exe" gui --uninstall`,
	} {
		if v := vals[name]; v.IsDword || v.Text != want {
			t.Errorf("%s = %+v, want %q", name, v, want)
		}
	}
	for name, want := range map[string]uint32{"NoModify": 1, "NoRepair": 1, "EstimatedSize": 98765} {
		if v := vals[name]; !v.IsDword || v.Dword != want {
			t.Errorf("%s = %+v, want %d", name, v, want)
		}
	}
}

func validJournal() Journal {
	return Journal{From: "1.2.0", To: "1.3.0", Step: StepSwapped,
		OldHash: strings.Repeat("a", 64), NewHash: strings.Repeat("b", 64),
		Started: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC), PID: 4242}
}

func TestJournalRoundTrip(t *testing.T) {
	j := validJournal()
	b, err := j.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeJournal(b)
	if err != nil || got != j {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"unknown step":  strings.Replace(string(b), `"swapped"`, `"done"`, 1),
		"bad version":   strings.Replace(string(b), `"1.3.0"`, `"latest"`, 1),
		"short hash":    strings.Replace(string(b), strings.Repeat("b", 64), "bb", 1),
		"capital hash":  strings.Replace(string(b), strings.Repeat("b", 64), strings.Repeat("B", 64), 1),
		"unknown field": strings.Replace(string(b), `{`, `{"x":1,`, 1),
		"trailing data": string(b) + `{}`,
		"empty":         ``,
		"too large":     string(b) + strings.Repeat(" ", maxJournal),
		"not an object": `[]`,
		"no process id": strings.Replace(string(b), `"pid":4242`, `"pid":0`, 1),
	} {
		if _, err := DecodeJournal([]byte(bad)); err == nil {
			t.Errorf("%s: DecodeJournal accepted %q", name, bad)
		}
	}
}

// TestDecide: before the swap an interrupted update is cleaned up; after it,
// the update is kept only if the new version had finished and is the file
// in place, and rolled back otherwise.
func TestDecide(t *testing.T) {
	j := validJournal()
	for _, tt := range []struct {
		step      Step
		installed string
		want      Recovery
	}{
		{StepVerified, j.OldHash, RecoverCleanup},
		{StepSnapshot, j.OldHash, RecoverCleanup},
		{StepStaged, j.OldHash, RecoverCleanup},
		{StepStopped, j.OldHash, RecoverCleanup},
		{StepSwapped, j.NewHash, RecoverRollback},
		{StepSwapped, "", RecoverRollback},
		{StepFinished, j.NewHash, RecoverConfirm},
		{StepFinished, j.OldHash, RecoverRollback},
		{StepFinished, "", RecoverRollback},
		{StepRollingBack, j.NewHash, RecoverRollback},
		{StepRollingBack, j.OldHash, RecoverRollback},
	} {
		j.Step = tt.step
		if got := Decide(j, tt.installed); got != tt.want {
			t.Errorf("step %s, installed %.4s: %v, want %v", tt.step, tt.installed, got, tt.want)
		}
	}
	for _, s := range steps {
		j.Step = s
		if Decide(j, "") == 0 {
			t.Errorf("step %s has no recovery", s)
		}
	}
}

// TestRollbackResult: a rollback is reported as such only when it worked;
// one that could not put the previous version back is a plain failure that
// names both causes (review finding of 20 Nov 2026).
func TestRollbackResult(t *testing.T) {
	cause := errors.New("the new supervisor did not answer")
	ok := rollbackResult("1.2.0", cause, nil)
	if ExitCode(ok) != CodeRolledBack || !errors.Is(ok, cause) {
		t.Fatalf("clean rollback: code %d, %v", ExitCode(ok), ok)
	}
	restore := errors.New("soireehost.exe.previous is locked")
	bad := rollbackResult("1.2.0", cause, []error{restore})
	if ExitCode(bad) != CodeFailed || !errors.Is(bad, cause) || !errors.Is(bad, restore) {
		t.Fatalf("failed rollback: code %d, %v", ExitCode(bad), bad)
	}
}

// FuzzDecodeJournal: no input panics the journal reader, and anything it
// accepts round-trips and has a recovery.
func FuzzDecodeJournal(f *testing.F) {
	b, _ := validJournal().Encode()
	f.Add(b)
	f.Add([]byte(`{"from":"1.0.0","to":"1.0.1","step":"finished"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		j, err := DecodeJournal(data)
		if err != nil {
			return
		}
		if Decide(j, "") == 0 || Decide(j, j.NewHash) == 0 {
			t.Fatalf("no recovery for %+v", j)
		}
		again, err := j.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if k, err := DecodeJournal(again); err != nil || !k.Started.Equal(j.Started) || k.Step != j.Step {
			t.Fatalf("round trip: %+v, %v", k, err)
		}
	})
}

// TestSignatureAllows is the S-61 decision table.
func TestSignatureAllows(t *testing.T) {
	const pub, other = "SoiréeHost project", "Someone Else"
	for _, tt := range []struct {
		name       string
		runValid   bool
		runSubject string
		newValid   bool
		newSubject string
		ok         bool
		runSigned  bool
	}{
		{"unsigned to unsigned", false, "", false, "", true, false},
		{"unsigned to signed", false, "", true, pub, true, false},
		{"signed to signed, same publisher", true, pub, true, pub, true, true},
		{"signed to unsigned", true, pub, false, "", false, true},
		{"signed to another publisher", true, pub, true, other, false, true},
		{"signed to a broken signature claiming the publisher", true, pub, false, pub, false, true},
		{"signed, publisher unreadable", true, "", true, "", false, true},
		{"publisher differs only in case", true, pub, true, "soiréehost project", false, true},
		// the running program's own signature does not verify here (expired,
		// uncached chain): never treated as unsigned
		{"signed but not verifying, to unsigned", false, "", false, "", false, true},
		{"signed but not verifying, to signed", false, "", true, pub, false, true},
	} {
		err := signatureAllows(tt.runSigned, tt.runValid, tt.runSubject, tt.newValid, tt.newSubject)
		if (err == nil) != tt.ok {
			t.Errorf("%s: %v", tt.name, err)
		}
		if err != nil && ExitCode(err) != CodeUpdateRefused {
			t.Errorf("%s: exit code %d, want %d", tt.name, ExitCode(err), CodeUpdateRefused)
		}
	}
}

// TestEventFor: setup's event log entries (ADR-0010) name the command and
// the exit code; a rolled-back update is a warning tagged update.rollback.
func TestEventFor(t *testing.T) {
	if k, id, text := eventFor(CmdInstall, nil); k != eventInfo || id != 1 || !strings.Contains(text, "setup install finished") {
		t.Fatalf("success: %d %d %q", k, id, text)
	}
	rolled := fail(CodeRolledBack, errors.New("the new supervisor did not answer"))
	if k, id, text := eventFor(CmdApplyUpdate, rolled); k != eventWarning || id != uint32(CodeRolledBack) ||
		!strings.HasPrefix(text, "update.rollback: setup apply-update") || !strings.Contains(text, "did not answer") {
		t.Fatalf("rollback: %d %d %q", k, id, text)
	}
	if k, id, text := eventFor(CmdRepair, errors.New("disk full")); k != eventError || id != uint32(CodeFailed) || !strings.Contains(text, "code 1: disk full") {
		t.Fatalf("failure: %d %d %q", k, id, text)
	}
	for _, c := range Codes() {
		if c > 1000 {
			t.Fatalf("exit code %d is outside the event ids EventCreate covers", c)
		}
	}
}
