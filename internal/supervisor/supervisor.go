// Package supervisor is the SoiréeHost service: it validates and stores the
// config, keeps secrets, starts and watches the two workers, serves the
// control pipe and writes the audit log (plan section 4, ADR-0001, ADR-0006).
// It never parses internet traffic.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fsutil"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Paths are the folders under %ProgramData%\SoireeHost.
type Paths struct {
	Root string
}

// Config is the config store folder.
func (p Paths) Config() string { return filepath.Join(p.Root, "config") }

// Secrets is the DPAPI blob folder.
func (p Paths) Secrets() string { return filepath.Join(p.Root, "secrets") }

// Logs is the parent log folder.
func (p Paths) Logs() string { return filepath.Join(p.Root, "logs") }

// Audit is the audit log folder.
func (p Paths) Audit() string { return filepath.Join(p.Root, "logs", "audit") }

// WebLogs is the web worker's log folder.
func (p Paths) WebLogs() string { return filepath.Join(p.Root, "logs", "web") }

// TunnelLogs is the tunnel launcher's log folder.
func (p Paths) TunnelLogs() string { return filepath.Join(p.Root, "logs", "tunnel") }

// Updates is the downloaded-updates folder (Phase 6).
func (p Paths) Updates() string { return filepath.Join(p.Root, "updates") }

// ControlUsersFile lists the accounts setup allowed on the control pipe.
func (p Paths) ControlUsersFile() string { return filepath.Join(p.Config(), "control-users.json") }

// Identity holds the SIDs of the three service accounts.
type Identity struct {
	Supervisor string
	Web        string
	Tunnel     string
}

// ServiceIdentity is the production identity: the three virtual accounts.
func ServiceIdentity() Identity {
	return Identity{
		Supervisor: winsec.ServiceSID(winsec.SupervisorService),
		Web:        winsec.ServiceSID(winsec.WebService),
		Tunnel:     winsec.ServiceSID(winsec.TunnelService),
	}
}

// ServiceControl starts and stops the worker services. In production this is
// the Windows service control manager; tests start in-process workers.
type ServiceControl interface {
	Start(service string) error
	Stop(service string) error
}

// Pipes are the pipe names: random at every start in production (DR-1),
// unique in tests.
type Pipes struct {
	Control, Web, Tunnel string
}

// NewPipes returns a new random name for each pipe.
func NewPipes() (Pipes, error) {
	var p Pipes
	var err error
	if p.Control, err = ipc.NewPipeName(ipc.ControlPipePrefix); err != nil {
		return Pipes{}, err
	}
	if p.Web, err = ipc.NewPipeName(ipc.WebPipePrefix); err != nil {
		return Pipes{}, err
	}
	if p.Tunnel, err = ipc.NewPipeName(ipc.TunnelPipePrefix); err != nil {
		return Pipes{}, err
	}
	return p, nil
}

// Options configure a supervisor.
type Options struct {
	Paths    Paths
	Identity Identity
	Pipes    Pipes
	Services ServiceControl
	Version  string
	// CheckACLs runs the S-22 folder check at start. Always true in the
	// service; tests that do not set the folders up turn it off.
	CheckACLs bool
	// CheckRoot resolves and checks a static site folder (sitecheck.CheckRoot
	// in production).
	CheckRoot func(root string) (string, error)
	// WorkerCanRead reports whether the web worker's account may read a
	// folder (winsec.GrantsRead in production). Nil skips the check.
	WorkerCanRead func(root string) (bool, error)
	// WorkerStartTimeout bounds the wait for a started worker to connect.
	WorkerStartTimeout time.Duration
	// LoadTimeout bounds the wait for a worker to apply a load.
	LoadTimeout time.Duration
}

// Supervisor is one running supervisor.
type Supervisor struct {
	opts     Options
	store    *config.Store
	secrets  *secrets.Store
	audit    *audit.Log
	auditMu  sync.Mutex
	auditRep audit.Report
	users    []string
	started  time.Time

	changeMu sync.Mutex // serialises config changes and their application
	web      *workerMgr
	tunnel   *workerMgr
}

// New checks the folders (S-22), opens the stores and verifies the audit log.
func New(opts Options) (*Supervisor, error) {
	if opts.WorkerStartTimeout == 0 {
		opts.WorkerStartTimeout = 30 * time.Second
	}
	if opts.LoadTimeout == 0 {
		opts.LoadTimeout = 30 * time.Second
	}
	if opts.CheckACLs {
		if err := checkFolders(opts.Paths, opts.Identity); err != nil {
			return nil, err
		}
	}
	store, err := config.OpenStore(opts.Paths.Config(), fsutil.WriteAtomic)
	if err != nil {
		return nil, err
	}
	sec, err := secrets.Open(opts.Paths.Secrets())
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Paths.Audit(), 0o700); err != nil {
		return nil, err
	}
	al, rep, err := audit.Open(filepath.Join(opts.Paths.Audit(), "audit.log"))
	if err != nil {
		return nil, err
	}
	users, err := readControlUsers(opts.Paths.ControlUsersFile())
	if err != nil {
		return nil, err
	}
	s := &Supervisor{opts: opts, store: store, secrets: sec, audit: al, auditRep: rep, users: users, started: time.Now()}
	s.web = newWorkerMgr(s, ipc.RoleWeb, winsec.WebService, opts.Identity.Web)
	s.tunnel = newWorkerMgr(s, ipc.RoleTunnel, winsec.TunnelService, opts.Identity.Tunnel)
	return s, nil
}

// checkFolders refuses to run if config can be written by anyone but SYSTEM,
// Administrators and the supervisor, or secrets by anyone but SYSTEM and the
// supervisor (S-22).
func checkFolders(p Paths, id Identity) error {
	if err := winsec.CheckWriters(p.Config(), winsec.SIDSystem, winsec.SIDAdministrators, id.Supervisor); err != nil {
		return fmt.Errorf("refusing to run: %w", err)
	}
	// secrets belong to the supervisor alone (ADR-0006); SYSTEM owns the folder
	if err := winsec.CheckWriters(p.Secrets(), winsec.SIDSystem, id.Supervisor); err != nil {
		return fmt.Errorf("refusing to run: %w", err)
	}
	return nil
}

// ControlUsers is the file setup writes to name the accounts allowed on the
// control pipe besides SYSTEM and elevated Administrators.
type ControlUsers struct {
	Users []string `json:"users"`
}

func readControlUsers(path string) ([]string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed path under the protected config folder
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cu ControlUsers
	if err := json.Unmarshal(b, &cu); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	for _, u := range cu.Users {
		if len(u) < 8 || u[:4] != "S-1-" {
			return nil, fmt.Errorf("reading %s: %q is not a SID", path, u)
		}
	}
	return cu.Users, nil
}

// authorize implements S-30: SYSTEM, an elevated administrator, or one of
// the accounts setup recorded.
func (s *Supervisor) authorize(c winsec.Caller) bool {
	return c.SID == winsec.SIDSystem || c.Admin || slices.Contains(s.users, c.SID)
}

// controlSDDL builds the control pipe descriptor for every allowed user.
func (s *Supervisor) controlSDDL() string {
	return winsec.ControlPipeSDDL(s.opts.Identity.Supervisor, s.users...)
}

// Run serves until ctx ends, then stops both workers.
func (s *Supervisor) Run(ctx context.Context) error {
	s.record(winsec.SIDSystem, "supervisor.start", map[string]string{"version": s.opts.Version, "audit_ok": fmt.Sprint(s.auditOK())})
	webLn, err := ipc.Listen(s.opts.Pipes.Web, winsec.WorkerPipeSDDL(s.opts.Identity.Supervisor, s.opts.Identity.Web))
	if err != nil {
		return err
	}
	tunLn, err := ipc.Listen(s.opts.Pipes.Tunnel, winsec.WorkerPipeSDDL(s.opts.Identity.Supervisor, s.opts.Identity.Tunnel))
	if err != nil {
		_ = webLn.Close()
		return err
	}
	ctlLn, err := ipc.Listen(s.opts.Pipes.Control, s.controlSDDL())
	if err != nil {
		_ = webLn.Close()
		_ = tunLn.Close()
		return err
	}
	if err := s.publishPipes(); err != nil {
		_ = webLn.Close()
		_ = tunLn.Close()
		_ = ctlLn.Close()
		return err
	}
	// If the control pipe stops serving for any reason, the workers stop too,
	// so Run never waits on managers that are still running.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.web.run(runCtx, webLn) }()
	go func() { defer wg.Done(); s.tunnel.run(runCtx, tunLn) }()
	err = ipc.ServeControl(runCtx, ctlLn, s.authorize, s.handle)
	cancel()
	wg.Wait()
	s.record(winsec.SIDSystem, "supervisor.stop", nil)
	return err
}

// publishPipes writes each pipe's random name to its pipe-name file, readable
// only by that pipe's clients (DR-1). It runs after the pipes exist and
// before any worker is started.
func (s *Supervisor) publishPipes() error {
	sup, id, p := s.opts.Identity.Supervisor, s.opts.Identity, s.opts.Paths
	files := []struct{ name, pipe, sddl string }{
		{ipc.WebPipeFile, s.opts.Pipes.Web, winsec.PipeNameFileSDDL(sup, id.Web)},
		{ipc.TunnelPipeFile, s.opts.Pipes.Tunnel, winsec.PipeNameFileSDDL(sup, id.Tunnel)},
		{ipc.ControlPipeFile, s.opts.Pipes.Control, winsec.PipeNameFileSDDL(sup, s.users...)},
	}
	for _, f := range files {
		if err := winsec.WriteFileSDDL(ipc.PipeFilePath(p.Root, f.name), f.sddl, []byte(f.pipe)); err != nil {
			return fmt.Errorf("publishing the %s pipe name: %w", f.name, err)
		}
	}
	return nil
}

// record writes an audit entry. A failure to audit is reported by status, and
// never stops the supervisor.
func (s *Supervisor) record(actor, action string, detail map[string]string) {
	if _, err := s.audit.Append(actor, action, detail); err != nil {
		s.auditMu.Lock()
		s.auditRep.Breaks = append(s.auditRep.Breaks, audit.Break{Reason: "could not write: " + err.Error()})
		s.auditMu.Unlock()
	}
}

// auditOK reports whether the audit log verified at start and every write
// since has succeeded.
func (s *Supervisor) auditOK() bool {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.auditRep.OK()
}

// current returns the revision in force, or a default config as revision 0.
func (s *Supervisor) current() (config.Record, error) {
	rec, err := s.store.Current()
	if errors.Is(err, config.ErrNoConfig) {
		return config.Record{Config: config.Default()}, nil
	}
	return rec, err
}
