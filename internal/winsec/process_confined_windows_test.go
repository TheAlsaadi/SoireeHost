package winsec

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestStartConfinedFromConfinedLauncher: the tunnel launcher confines
// itself first (its own job, privileges trimmed) and then starts cloudflared
// with StartConfined, a job nested in its own. This runs that order in a
// fresh copy of the test binary, as the installed service does.
func TestStartConfinedFromConfinedLauncher(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestConfinedLauncherHelper$", "-test.v") //nolint:gosec // G204: re-runs this test binary
	cmd.Env = append(os.Environ(), "SOIREEHOST_LAUNCHER_HELPER=1")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "LAUNCHER-CHILD-RAN") {
		t.Fatalf("a confined launcher could not start a confined child:\n%s", out)
	}
}

// TestConfinedLauncherHelper does something only when started by
// TestStartConfinedFromConfinedLauncher.
func TestConfinedLauncherHelper(t *testing.T) {
	if os.Getenv("SOIREEHOST_LAUNCHER_HELPER") != "1" {
		t.Skip("helper")
	}
	if err := RestrictDLLSearch(); err != nil {
		fmt.Println("DLL-ERROR", err)
		return
	}
	// the tunnel launcher's own limits (tunnel.Limits)
	if err := Confine(Limits{MemoryBytes: 256 << 20, ActiveProcesses: 6}); err != nil {
		fmt.Println("CONFINE-ERROR", err)
		return
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Println("EXE-ERROR", err)
		return
	}
	p, err := StartConfined(ProcessSpec{
		Path:   self,
		Args:   []string{"-test.run=^TestConfinedChildHelper$", "-test.v"},
		Env:    []string{"SystemRoot=" + os.Getenv("SystemRoot"), "SOIREEHOST_CHILD_HELPER=1"},
		Limits: Limits{MemoryBytes: 256 << 20, ActiveProcesses: 1},
	})
	if err != nil {
		fmt.Println("START-ERROR", err)
		return
	}
	defer p.Close() //nolint:errcheck // test helper
	out, _ := io.ReadAll(p.Output)
	code, err := p.Wait()
	fmt.Printf("child exit %d %v\n%s\n", code, err, out)
	if code == 0 && strings.Contains(string(out), "CHILD-SPAWN refused") {
		fmt.Println("LAUNCHER-CHILD-RAN")
	}
}
