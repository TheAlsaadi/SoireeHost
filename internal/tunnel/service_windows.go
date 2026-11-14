package tunnel

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/svcrun"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Limits are the tunnel launcher's own limits (S-21): itself plus one
// cloudflared for the token and one per quick share, 256 MB each. Child
// processes stay allowed because it must start cloudflared; each cloudflared
// gets a job of its own that allows it none (CloudflaredLimits).
var Limits = winsec.Limits{MemoryBytes: 256 << 20, ActiveProcesses: 2 + config.MaxQuickShares}

// RunService runs the tunnel launcher as the SoireeHostTunnel service.
func RunService(version string) error {
	return svcrun.Run(winsec.TunnelService, false, func(ctx context.Context) error {
		if err := winsec.Confine(Limits); err != nil {
			return fmt.Errorf("refusing to run unconfined: %w", err)
		}
		root, err := ipc.DataRoot()
		if err != nil {
			return err
		}
		exe, err := InstalledExe()
		if err != nil {
			return err
		}
		return Serve(ctx, ServeOptions{
			PipeFile:      ipc.PipeFilePath(root, ipc.TunnelPipeFile),
			SupervisorSID: winsec.ServiceSID(winsec.SupervisorService),
			Version:       version,
			Launcher: Options{
				Exe:     exe,
				SHA256:  CloudflaredSHA256,
				LogDir:  filepath.Join(root, "logs", "tunnel"),
				BaseEnv: ServiceEnv(),
			},
		})
	})
}

// ServeOptions configure Serve.
type ServeOptions struct {
	Pipe, PipeFile string
	SupervisorSID  string
	Version        string
	Launcher       Options
}

// Serve connects to the supervisor and runs the tunnels it asks for until
// the pipe closes; then every cloudflared is stopped.
func Serve(ctx context.Context, o ServeOptions) error {
	notify := make(chan ipc.WorkerMsg)
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lo := o.Launcher
	lo.Report = func(r ipc.TunnelReport) {
		select {
		case notify <- ipc.WorkerMsg{Type: ipc.MsgStatus, Report: &r}:
		case <-lctx.Done():
		}
	}
	l, err := New(lo)
	if err != nil {
		return err
	}
	return ipc.RunAgent(ctx, ipc.AgentOptions{
		Pipe:          o.Pipe,
		PipeFile:      o.PipeFile,
		SupervisorSID: o.SupervisorSID,
		Role:          ipc.RoleTunnel,
		Version:       o.Version,
		Notify:        notify,
		Load: func(m ipc.WorkerMsg) error {
			if m.Tunnel == nil {
				return fmt.Errorf("no tunnel plan")
			}
			return l.Apply(*m.Tunnel)
		},
		Stop: func() {
			cancel()
			l.Close()
		},
	})
}
