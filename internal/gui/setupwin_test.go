package gui

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

type fakeHost struct {
	installed bool
	ver       string
	self      string
	code      int
	cancelled bool
	ran       []string // "exe|args" of every elevated run
	quits     int
}

const testInstalledExe = `C:\Program Files\SoireeHost\soireehost.exe`

func (h *fakeHost) serviceInstalled() bool   { return h.installed }
func (h *fakeHost) installedVersion() string { return h.ver }
func (h *fakeHost) installedExe() string     { return testInstalledExe }
func (h *fakeHost) thisExe() (string, error) { return h.self, nil }
func (h *fakeHost) quit()                    { h.quits++ }
func (h *fakeHost) runElevated(exe, args string) (int, bool, error) {
	h.ran = append(h.ran, exe+"|"+args)
	return h.code, h.cancelled, nil
}

func TestSetupState(t *testing.T) {
	orig := version.Version
	t.Cleanup(func() { version.Version = orig })
	version.Version = "1.3.0"
	dl := `C:\Users\me\Downloads\soireehost.exe`
	for _, tt := range []struct {
		name      string
		h         fakeHost
		uninstall bool
		mode      string
		newer     bool
	}{
		{"nothing installed", fakeHost{self: dl}, false, ModeNotInstalled, true},
		{"the installed program", fakeHost{installed: true, ver: "1.3.0", self: testInstalledExe}, false, ModeInstalled, false},
		{"installed program, path in other case", fakeHost{installed: true, ver: "1.3.0", self: `c:\program files\soireehost\SOIREEHOST.EXE`}, false, ModeInstalled, false},
		{"an older install, this copy newer", fakeHost{installed: true, ver: "1.2.0", self: dl}, false, ModeOtherCopy, true},
		{"a newer install, this copy older", fakeHost{installed: true, ver: "1.4.0", self: dl}, false, ModeOtherCopy, false},
		{"an install from before Phase 6", fakeHost{installed: true, self: dl}, false, ModeOtherCopy, true},
		{"opened from Settings > Apps", fakeHost{installed: true, ver: "1.3.0", self: testInstalledExe}, true, ModeUninstall, false},
	} {
		got := setupState(&tt.h, tt.uninstall)
		if got.Mode != tt.mode || got.Newer != tt.newer || got.ThisVersion != "1.3.0" {
			t.Errorf("%s: %+v, want mode %s, newer %v", tt.name, got, tt.mode, tt.newer)
		}
	}
}

// TestSetupActions: each action runs a fixed command, install from this
// copy and everything else from the installed program; nothing else is
// accepted (ADR-0010).
func TestSetupActions(t *testing.T) {
	dl := `C:\Users\me\Downloads\soireehost.exe`
	h := &fakeHost{installed: true, self: dl}
	for action, want := range map[string]string{
		ActionInstall:        dl + "|setup install",
		ActionRepair:         testInstalledExe + "|setup repair",
		ActionApplyUpdate:    testInstalledExe + "|setup apply-update",
		ActionUninstall:      testInstalledExe + "|setup uninstall",
		ActionUninstallPurge: testInstalledExe + "|setup uninstall --purge",
	} {
		exe, args, err := setupCommand(h, action)
		if err != nil || exe+"|"+args != want {
			t.Errorf("%s: %s|%s, %v; want %s", action, exe, args, err, want)
		}
	}
	for _, bad := range []string{"", "Install", "setup install", "uninstall --purge", `install C:\x.exe`, "repair;calc"} {
		if _, _, err := setupCommand(h, bad); err == nil {
			t.Errorf("accepted action %q", bad)
		}
	}
}

func TestSetupRun(t *testing.T) {
	h := &fakeHost{installed: true, self: testInstalledExe}
	s := NewSetup(h, false)
	if _, err := s.Run("format-c"); err == nil || len(h.ran) != 0 {
		t.Fatal("an unknown action reached the Windows prompt")
	}
	h.cancelled = true
	res, err := s.Run(ActionRepair)
	if err != nil || !res.Cancelled || s.relaunch {
		t.Fatalf("declined prompt: %+v, %v", res, err)
	}
	h.cancelled, h.code = false, int(setup.CodeRolledBack)
	if res, _ := s.Run(ActionApplyUpdate); res.Code != int(setup.CodeRolledBack) || s.relaunch {
		t.Fatalf("rolled-back update: %+v, relaunch %v", res, s.relaunch)
	}
	h.code = 0
	if res, _ := s.Run(ActionApplyUpdate); res.Code != 0 || !s.relaunch {
		t.Fatalf("installed update: %+v, relaunch %v", res, s.relaunch)
	}
	s.OpenInstalled()
	if h.quits != 1 {
		t.Fatalf("OpenInstalled quit %d times", h.quits)
	}
}

// TestSetupCodesHaveSentences: every setup exit code has a sentence in the
// control panel's message catalogue, so no result shows as a bare number.
func TestSetupCodesHaveSentences(t *testing.T) {
	b, err := os.ReadFile("../../frontend/src/lib/i18n/en.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range setup.Codes() {
		if c == setup.CodeOK {
			continue
		}
		key := `"setup.code.` + strconv.Itoa(int(c)) + `":`
		if !regexp.MustCompile(regexp.QuoteMeta(key)).Match(b) {
			t.Errorf("no catalogue entry %s", key)
		}
	}
}

func TestParseArgsUninstall(t *testing.T) {
	if o, err := ParseArgs([]string{"--uninstall"}); err != nil || !o.Uninstall {
		t.Fatalf("--uninstall: %+v, %v", o, err)
	}
	if _, err := ParseArgs([]string{"--tray", "--uninstall"}); err == nil {
		t.Fatal("accepted --tray with --uninstall")
	}
	if _, err := ParseArgs([]string{"--uninstall", "--purge"}); err == nil {
		t.Fatal("accepted --purge: the window asks, the command line does not decide")
	}
}
