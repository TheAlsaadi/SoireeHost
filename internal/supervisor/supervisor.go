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
	// SkipACLCheck leaves out the S-22 folder check at start, for tests
	// that do not set the folders up. The zero value checks (review
	// finding SE-22: a forgotten field must not turn S-22 off).
	SkipACLCheck bool
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
	// PortFree reports whether a loopback port is free for a new quick
	// share (LoopbackPortFree when nil).
	PortFree func(port int) bool
	// Updates turns the update check on (ADR-0004). Nil leaves it out, as
	// most tests do; status then reports it off.
	Updates *UpdateOptions
	// UpdateJournal is apply-update's journal in the program folder
	// (UpdateJournalName beside soireehost.exe). Status reports an update
	// as interrupted while one is there and has not changed for
	// updateStalled (S-63). Empty skips the check, as most tests do.
	UpdateJournal string
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
	// connectLost counts the web worker's connects in a row whose load of
	// one revision it never finished (S-41); guarded by changeMu
	connectLost struct {
		revision uint64
		times    int
	}
	tunnelMu sync.Mutex // serialises tunnel plans and secret.set (GO-6); taken after changeMu
	web      *workerMgr
	tunnel   *workerMgr

	tmu    sync.Mutex // guards tstate
	tstate tunnelState

	conf *confirmations // open confirmation tokens (S-32, SE-27)
	upd  *updater       // nil when Options.Updates is nil
}

// New checks the folders (S-22), opens the stores and verifies the audit log.
func New(opts Options) (*Supervisor, error) {
	if opts.WorkerStartTimeout == 0 {
		opts.WorkerStartTimeout = 30 * time.Second
	}
	if opts.LoadTimeout == 0 {
		opts.LoadTimeout = 30 * time.Second
	}
	if opts.PortFree == nil {
		opts.PortFree = LoopbackPortFree
	}
	if !filepath.IsAbs(opts.Paths.Root) {
		return nil, fmt.Errorf("refusing to run: the data folder %q is not an absolute path", opts.Paths.Root)
	}
	if !opts.SkipACLCheck {
		// the check reads writers only, so the control users do not matter
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
	s := &Supervisor{opts: opts, store: store, secrets: sec, audit: al, auditRep: rep, users: users, started: time.Now(), conf: newConfirmations(nil)}
	s.web = newWorkerMgr(s, ipc.RoleWeb, winsec.WebService, opts.Identity.Web)
	s.tunnel = newWorkerMgr(s, ipc.RoleTunnel, winsec.TunnelService, opts.Identity.Tunnel)
	if opts.Updates != nil {
		s.upd = newUpdater(opts.Paths.Updates(), opts.Version, *opts.Updates, s.updatesEnabled,
			func(action string, detail map[string]string) { _ = s.record(winsec.SIDSystem, action, detail) })
	}
	return s, nil
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
		if _, err := winsec.UserSID(u); err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
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
	_ = s.record(winsec.SIDSystem, "supervisor.start", map[string]string{"version": s.opts.Version, "audit_ok": fmt.Sprint(s.auditOK())})
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
	if s.upd != nil {
		wg.Go(func() { s.upd.run(runCtx) })
	}
	err = ipc.ServeControl(runCtx, ctlLn, s.authorize, s.handle)
	cancel()
	wg.Wait()
	_ = s.record(winsec.SIDSystem, "supervisor.stop", nil)
	return err
}

// publishPipes writes each pipe's random name to its pipe-name file, readable
// only by that pipe's clients (DR-1). It runs after the pipes exist and
// before any worker is started. Each file goes in the folder setup made for
// it and takes that folder's permissions (winsec.PipeNameFolderSDDL); the
// supervisor never creates the folders, so a missing one stops it rather
// than publishing a name its clients cannot read.
func (s *Supervisor) publishPipes() error {
	root := s.opts.Paths.Root
	files := []struct{ name, pipe string }{
		{ipc.WebPipeFile, s.opts.Pipes.Web},
		{ipc.TunnelPipeFile, s.opts.Pipes.Tunnel},
		{ipc.ControlPipeFile, s.opts.Pipes.Control},
	}
	for _, f := range files {
		if err := fsutil.WriteAtomic(ipc.PipeFilePath(root, f.name), []byte(f.pipe)); err != nil {
			return fmt.Errorf("publishing the %s pipe name (run setup again if its folder is missing): %w", f.name, err)
		}
	}
	return nil
}

// record writes an audit entry. A failure to audit is reported by status and
// returned; it never stops the supervisor. Callers that make a weakening
// change undo it when the entry cannot be written (S-32).
func (s *Supervisor) record(actor, action string, detail map[string]string) error {
	if _, err := s.audit.Append(actor, action, detail); err != nil {
		s.auditMu.Lock()
		s.auditRep.Breaks = append(s.auditRep.Breaks, audit.Break{Reason: "could not write: " + err.Error()})
		s.auditMu.Unlock()
		return err
	}
	return nil
}

// errNotAudited is the answer to a weakening change that was undone because
// its audit entry could not be written (S-32).
var errNotAudited = ipc.Errorf(ipc.CodeUnavailable, "The change was not made, because the audit log could not be written. Check the Security page.")

// auditOK reports whether the audit log verified at start and every write
// since has succeeded.
func (s *Supervisor) auditOK() bool {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.auditRep.OK()
}

// updatesEnabled reports whether the update check is on in the settings in
// force.
func (s *Supervisor) updatesEnabled() bool {
	rec, err := s.current()
	return err == nil && !rec.Config.Updates.Off
}

// current returns the revision in force, or a default config as revision 0.
func (s *Supervisor) current() (config.Record, error) {
	rec, err := s.store.Current()
	if errors.Is(err, config.ErrNoConfig) {
		return config.Record{Config: config.Default()}, nil
	}
	return rec, err
}
