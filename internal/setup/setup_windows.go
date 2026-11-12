// Package setup is the elevated setup role: install and uninstall (Phase 2
// subset; Phase 6 adds the Windows prompt, repair, updates, the Apps entry
// and self-removal). See docs/adr/0006-supervisor-ipc-and-stores.md.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/supervisor"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Layout is where setup puts things.
type Layout struct {
	ProgramDir string // %ProgramFiles%\SoireeHost
	DataRoot   string // %ProgramData%\SoireeHost
}

// Exe is the installed binary.
func (l Layout) Exe() string { return filepath.Join(l.ProgramDir, "soireehost.exe") }

// DefaultLayout reads the folders from Windows.
func DefaultLayout() (Layout, error) {
	loc, err := sitecheck.DefaultLocations()
	if err != nil {
		return Layout{}, err
	}
	return Layout{
		ProgramDir: filepath.Join(loc.ProgramFiles[0], "SoireeHost"),
		DataRoot:   filepath.Join(loc.ProgramData, "SoireeHost"),
	}, nil
}

type serviceSpec struct {
	name, display, description, role string
	start                            uint32
}

var services = []serviceSpec{
	{winsec.SupervisorService, "SoiréeHost", "Runs SoiréeHost: keeps settings and secrets, and starts the web server and tunnel.", "service", mgr.StartAutomatic},
	{winsec.WebService, "SoiréeHost web server", "Serves SoiréeHost sites on this PC only. Started by SoiréeHost.", "worker", mgr.StartManual},
	{winsec.TunnelService, "SoiréeHost tunnel", "Connects SoiréeHost to Cloudflare. Started by SoiréeHost.", "tunnel", mgr.StartManual},
}

// Install installs SoiréeHost from the running binary. It must run elevated.
func Install(l Layout) error {
	me, err := winsec.CurrentCaller()
	if err != nil {
		return err
	}
	if !me.Admin {
		return errors.New("setup must run from an elevated (administrator) prompt")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := winsec.EnablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	// a running install holds the binary open; stop it before replacing it
	stopInstalled()
	if err := copyBinary(self, l.Exe()); err != nil {
		return fmt.Errorf("copying the program: %w", err)
	}
	if err := checkDataRoot(l.DataRoot); err != nil {
		return err
	}
	if err := makeFolders(l.DataRoot); err != nil {
		return fmt.Errorf("creating data folders: %w", err)
	}
	if err := writeControlUsers(l.DataRoot, me.SID); err != nil {
		return err
	}
	if err := registerServices(l.Exe()); err != nil {
		return err
	}
	registerEventSources()
	return startService(winsec.SupervisorService)
}

// copyBinary copies src to dst unless they are the same file.
func copyBinary(src, dst string) error {
	if a, err := filepath.Abs(src); err == nil && strings.EqualFold(a, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- Program Files permissions are inherited from Windows (Administrators write, Users read)
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- the running executable
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- program file under Program Files
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(tmp)
	to, _ := windows.UTF16PtrFromString(dst)
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// makeFolders creates %ProgramData%\SoireeHost and its subfolders with the
// ADR-0006 descriptors.
func makeFolders(root string) error {
	sup, web, tun := winsec.ServiceSID(winsec.SupervisorService), winsec.ServiceSID(winsec.WebService), winsec.ServiceSID(winsec.TunnelService)
	p := supervisor.Paths{Root: root}
	// Every folder gets an explicit owner, so nothing created earlier by
	// another account keeps an owner's rights. Secrets are owned by SYSTEM:
	// the supervisor's S-22 check allows no one else there.
	ba, sy := "O:"+winsec.SIDAdministrators, "O:"+winsec.SIDSystem
	steps := []struct{ path, sddl string }{
		{root, ba + winsec.DataRootSDDL(sup, web, tun)},
		{p.Config(), ba + winsec.ConfigFolderSDDL(sup)},
		{p.Secrets(), sy + winsec.SecretsFolderSDDL(sup)},
		{p.Logs(), ba + winsec.LogsFolderSDDL(sup)},
		{p.Audit(), ba + winsec.AuditFolderSDDL(sup)},
		{p.WebLogs(), ba + winsec.WorkerLogFolderSDDL(sup, web)},
		{p.TunnelLogs(), ba + winsec.WorkerLogFolderSDDL(sup, tun)},
		{p.Updates(), ba + winsec.UpdatesFolderSDDL(sup)},
	}
	for _, s := range steps {
		fi, err := os.Lstat(s.path)
		if errors.Is(err, os.ErrNotExist) {
			// A new folder is created with its final descriptor in the same
			// call. Created any other way it would carry %ProgramData%'s
			// permissions for a moment, long enough for a standard user to
			// plant a subfolder or file inside it (Phase 2 security review).
			if err := winsec.CreateFolderSDDL(s.path, s.sddl); err != nil {
				return fmt.Errorf("%s: %w", s.path, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", s.path, err)
		}
		if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("refusing to install: %s is not a plain folder (a link or junction?)", s.path)
		}
		// on a reinstall the folders already lock out even their owner, so
		// the descriptor is written with SeRestorePrivilege
		if err := winsec.ForceSDDL(s.path, s.sddl); err != nil {
			return fmt.Errorf("%s: %w", s.path, err)
		}
	}
	return nil
}

// checkDataRoot refuses an existing %ProgramData%\SoireeHost that is a link
// or junction, or that is owned by anyone but Administrators or SYSTEM. A
// standard user can create folders in %ProgramData%, so one could create
// this folder before the first install, plant a config or a junction in it,
// and keep an owner's rights over it.
func checkDataRoot(root string) error {
	fi, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("refusing to install: %s is not a plain folder (a link or junction?); delete it and run setup again", root)
	}
	sd, err := windows.GetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the owner of %s: %w", root, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s has no owner", root)
	}
	if o := owner.String(); o != winsec.SIDAdministrators && o != winsec.SIDSystem {
		return fmt.Errorf("refusing to install: %s already exists and was created by another account (%s); delete it and run setup again", root, o)
	}
	return nil
}

// registerEventSources lets each service write to the Application event
// log under its own name. A source that already exists is replaced.
func registerEventSources() {
	for _, spec := range services {
		_ = eventlog.Remove(spec.name)
		_ = eventlog.InstallAsEventCreate(spec.name, eventlog.Error|eventlog.Warning|eventlog.Info)
	}
}

// stopInstalled stops the three services if they exist, supervisor first.
func stopInstalled() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	for _, spec := range services {
		if s, err := m.OpenService(spec.name); err == nil {
			stopAndWait(s)
			_ = s.Close()
		}
	}
}

func writeControlUsers(root, user string) error {
	b, err := json.Marshal(supervisor.ControlUsers{Users: []string{user}})
	if err != nil {
		return err
	}
	// Delete and create anew, so the file always takes the config folder's
	// descriptor instead of keeping whatever an earlier file had.
	p := supervisor.Paths{Root: root}.ControlUsersFile()
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- fixed path under the protected config folder
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	return errors.Join(werr, f.Close())
}

func registerServices(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	for _, spec := range services {
		cfg := mgr.Config{
			ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:        spec.start,
			ErrorControl:     mgr.ErrorNormal,
			DisplayName:      spec.display,
			Description:      spec.description,
			ServiceStartName: `NT SERVICE\` + spec.name,
			SidType:          windows.SERVICE_SID_TYPE_RESTRICTED,
		}
		s, err := m.OpenService(spec.name)
		if err == nil {
			cfg.BinaryPathName = quote(exe) + " " + spec.role
			err = s.UpdateConfig(cfg)
		} else {
			s, err = m.CreateService(spec.name, exe, cfg, spec.role)
		}
		if err != nil {
			return fmt.Errorf("registering %s: %w", spec.name, err)
		}
		err = configureService(s, spec)
		_ = s.Close()
		if err != nil {
			return fmt.Errorf("configuring %s: %w", spec.name, err)
		}
	}
	return nil
}

func quote(p string) string { return `"` + p + `"` }

// configureService trims privileges, sets recovery for the supervisor, and
// locks the worker services so only the supervisor may start and stop them.
func configureService(s *mgr.Service, spec serviceSpec) error {
	if err := setRequiredPrivileges(s.Handle, "SeChangeNotifyPrivilege"); err != nil {
		return err
	}
	if spec.name == winsec.SupervisorService {
		actions := []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		}
		if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
			return err
		}
		return s.SetRecoveryActionsOnNonCrashFailures(true)
	}
	sd, err := windows.SecurityDescriptorFromString(winsec.WorkerServiceSDDL(winsec.ServiceSID(winsec.SupervisorService)))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// setRequiredPrivileges sets SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO: the
// service's token gets only these privileges (S-20).
func setRequiredPrivileges(h windows.Handle, privs ...string) error {
	var multi []uint16
	for _, p := range privs {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			return err
		}
		multi = append(multi, u...)
	}
	multi = append(multi, 0)
	info := struct{ privileges *uint16 }{&multi[0]}
	// #nosec G103 -- SERVICE_REQUIRED_PRIVILEGES_INFO is one pointer to a multi-string, as the API defines
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info)))
}

func startService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close() //nolint:errcheck // nothing to do on failure
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("starting %s: %w", name, err)
	}
	return nil
}

// Uninstall stops and removes the three services and the program folder.
// With purge it also removes %ProgramData%\SoireeHost, taking ownership of
// folders that only the services could otherwise open.
func Uninstall(l Layout, purge bool) error {
	me, err := winsec.CurrentCaller()
	if err != nil {
		return err
	}
	if !me.Admin {
		return errors.New("setup must run from an elevated (administrator) prompt")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	var errs []error
	// supervisor first: it stops both workers itself
	for _, spec := range services {
		s, err := m.OpenService(spec.name)
		if err != nil {
			continue
		}
		stopAndWait(s)
		if err := s.Delete(); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", spec.name, err))
		}
		_ = s.Close()
		_ = eventlog.Remove(spec.name)
	}
	if self, err := os.Executable(); err == nil && strings.EqualFold(filepath.Dir(self), l.ProgramDir) {
		errs = append(errs, errors.New("run uninstall from a copy outside the program folder to remove it (self-removal comes in Phase 6)"))
	} else if err := os.RemoveAll(l.ProgramDir); err != nil {
		errs = append(errs, err)
	}
	if purge {
		if err := takeBack(l.DataRoot); err != nil {
			errs = append(errs, err)
		} else if err := os.RemoveAll(l.DataRoot); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func stopAndWait(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for st.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return
		}
	}
}

// takeBack makes Administrators owner of root and everything under it, with
// full control, so an elevated uninstall can delete folders that only the
// services could open.
func takeBack(root string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := winsec.EnablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	sddl := "O:" + winsec.SIDAdministrators + "D:P(A;OICI;FA;;;" + winsec.SIDAdministrators + ")"
	// WalkDir reads a folder only after the callback for it returns, so
	// taking it over here is what lets the walk see inside
	// A file with several hard links is not re-permissioned (that would
	// change its other ends too); RemoveAll unlinks it through the folder,
	// which Administrators then control.
	return filepath.WalkDir(root, func(p string, _ os.DirEntry, _ error) error {
		if _, err := winsec.ForceSDDLUnlessLinked(p, sddl); err != nil {
			return fmt.Errorf("taking ownership of %s: %w", p, err)
		}
		return nil
	})
}
