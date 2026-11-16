//go:build e2e

package e2e

import (
	"os/exec"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// ADR-0003, ADR-0009 (S-33): the installed control panel serves its UI from
// memory through WebView2 and never opens a listening socket. The test
// starts the installed soireehost.exe in the tray and watches its sockets
// for a while.
func TestControlPanelOpensNoPort(t *testing.T) {
	waitAllRunning(t)
	cmd := exec.CommandContext(t.Context(), layout(t).Exe(), "gui", "--tray") // #nosec G204 -- the installed program, fixed arguments
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	pid := uint32(cmd.Process.Pid) // #nosec G115 -- a Windows process id fits in 32 bits
	exited := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(exited)
	}()
	deadline := time.Now().Add(15 * time.Second)
	checks := 0
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			if checks == 0 {
				t.Fatal("the control panel exited at once")
			}
			return
		default:
		}
		eps, err := winsec.EndpointsOf(pid)
		if err != nil {
			t.Fatal(err)
		}
		if len(eps) > 0 {
			t.Fatalf("the control panel listens: %+v", eps)
		}
		checks++
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("no listening socket in %d checks over 15 s", checks)
}
