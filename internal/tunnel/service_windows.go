// Package tunnel is the tunnel launcher. In Phase 2 it confines itself,
// connects to the supervisor and holds the tunnel token in memory; Phase 3
// adds starting the embedded cloudflared with it.
package tunnel

import (
	"context"
	"fmt"
	"sync"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Limits are the tunnel launcher's limits (S-21): itself plus cloudflared,
// 256 MB each. Child processes stay allowed because it must start
// cloudflared; the job allows exactly one.
var Limits = winsec.Limits{MemoryBytes: 256 << 20, ActiveProcesses: 2}

// tokenHolder keeps the token in memory only.
type tokenHolder struct {
	mu    sync.Mutex
	token string
}

func (t *tokenHolder) set(tok string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = tok
}

// RunService runs the tunnel launcher as the SoireeHostTunnel service.
func RunService(version string) error {
	return svcrun.Run(winsec.TunnelService, false, func(ctx context.Context) error {
		if err := winsec.Confine(Limits); err != nil {
			return fmt.Errorf("refusing to run unconfined: %w", err)
		}
		var tok tokenHolder
		return ipc.RunAgent(ctx, ipc.AgentOptions{
			Pipe:          ipc.TunnelPipe,
			SupervisorSID: winsec.ServiceSID(winsec.SupervisorService),
			Role:          ipc.RoleTunnel,
			Version:       version,
			Load:          func(m ipc.WorkerMsg) error { tok.set(m.Token); return nil },
			Stop:          func() { tok.set("") },
		})
	})
}
