//go:build e2e

package e2e

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/TheAlsaadi/SoireeHost/internal/setup"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

// TestAppsEntry: install wrote the Settings > Apps entry, which only
// administrators can change, and its uninstall command opens the control
// panel's uninstall window from the installed program (ADR-0010).
func TestAppsEntry(t *testing.T) {
	l := layout(t)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, setup.UninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatalf("no Apps entry: %v", err)
	}
	defer k.Close() //nolint:errcheck // read-only
	for name, want := range map[string]string{
		"DisplayName":     "SoiréeHost",
		"Publisher":       "SoiréeHost project",
		"InstallLocation": l.ProgramDir,
		"UninstallString": `"` + l.Exe() + `" gui --uninstall`,
		"DisplayIcon":     `"` + l.Exe() + `",0`,
	} {
		got, _, err := k.GetStringValue(name)
		if err != nil || got != want {
			t.Errorf("%s = %q (%v), want %q", name, got, err, want)
		}
	}
	if v, _, err := k.GetStringValue("DisplayVersion"); err != nil || !version.Valid(v) {
		t.Errorf("DisplayVersion = %q (%v)", v, err)
	}
	if n, _, err := k.GetIntegerValue("EstimatedSize"); err != nil || n == 0 {
		t.Errorf("EstimatedSize = %d (%v)", n, err)
	}
}

// TestSetupRefusesOtherCopiesAndArguments: repair and apply-update act only
// from the installed program, and no setup command takes an extra argument
// (ADR-0010). Neither call changes anything.
func TestSetupRefusesOtherCopiesAndArguments(t *testing.T) {
	l := layout(t)
	for _, tc := range []struct {
		exe  string
		args []string
		want setup.Code
	}{
		{l.Exe(), []string{"setup", "repair", "now"}, setup.CodeUsage},
		{l.Exe(), []string{"setup", "apply-update", `C:\Users\Public\soireehost.exe`}, setup.CodeUsage},
		{ciCopy, []string{"setup", "repair"}, setup.CodeNotInstalled},
	} {
		if _, err := os.Stat(tc.exe); err != nil {
			t.Skipf("%s is not here: %v", tc.exe, err)
		}
		err := exec.CommandContext(t.Context(), tc.exe, tc.args...).Run() // #nosec G204 -- fixed test arguments
		code := 0
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%s %v: %v", tc.exe, tc.args, err)
		}
		if setup.Code(code) != tc.want {
			t.Errorf("%s %v exited %d, want %d", tc.exe, tc.args, code, tc.want)
		}
	}
}

// ciCopy is where the CI isolation job keeps the binary it installed from.
const ciCopy = `C:\soireehost-ci\soireehost.exe`
