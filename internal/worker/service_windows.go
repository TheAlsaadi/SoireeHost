package worker

import (
	"context"
	"fmt"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Limits are the web worker's self-imposed limits (S-21): one process, no
// child processes, 1 GiB of memory.
var Limits = winsec.Limits{MemoryBytes: 1 << 30, ActiveProcesses: 1, NoChildProcesses: true}

// RunService runs the web worker as the SoireeHostWeb Windows service: it
// confines itself, connects to the supervisor, loads what it is sent, and
// exits when the supervisor's pipe closes.
func RunService(version string) error {
	return svcrun.Run(winsec.WebService, false, func(ctx context.Context) error {
		if err := winsec.Confine(Limits); err != nil {
			return fmt.Errorf("refusing to run unconfined: %w", err)
		}
		return ipc.RunAgent(ctx, ipc.AgentOptions{
			Pipe:          ipc.WebPipe,
			SupervisorSID: winsec.ServiceSID(winsec.SupervisorService),
			Role:          ipc.RoleWeb,
			Version:       version,
			Load:          func(m ipc.WorkerMsg) error { return LoadJSON(m.Caddy) },
			Stop:          func() { _ = Stop() },
		})
	})
}
