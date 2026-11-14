package worker

import (
	"context"
	"errors"
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
// exits when the supervisor's pipe closes. A failed listener self-check, at
// a load or in the once-a-minute repeat, ends the process (S-01, R-05).
func RunService(version string) error {
	return svcrun.Run(winsec.WebService, false, func(ctx context.Context) error {
		if err := winsec.Confine(Limits); err != nil {
			return fmt.Errorf("refusing to run unconfined: %w", err)
		}
		root, err := ipc.DataRoot()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		go func() {
			if err := WatchListeners(ctx, SelfCheckInterval); err != nil {
				cancel(err)
			}
		}()
		err = ipc.RunAgent(ctx, ipc.AgentOptions{
			PipeFile:      ipc.PipeFilePath(root, ipc.WebPipeFile),
			SupervisorSID: winsec.ServiceSID(winsec.SupervisorService),
			Role:          ipc.RoleWeb,
			Version:       version,
			Load:          loadOrExit,
			Stop:          func() { _ = Stop() },
		})
		if cause := context.Cause(ctx); errors.Is(cause, ErrSelfCheck) {
			return cause
		}
		return err
	})
}

// loadOrExit loads a config; a failed self-check also tells the agent to end
// the process once it has reported the failure.
func loadOrExit(m ipc.WorkerMsg) error {
	err := LoadJSON(m.Caddy)
	if errors.Is(err, ErrSelfCheck) {
		return fmt.Errorf("%w: %w", ipc.ErrAgentExit, err)
	}
	return err
}
