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
	"slices"
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
	// Open the program now, before anything waits, and keep it open: the
	// copy below reads this handle, so what is installed is the file that
	// was checked here, whatever happens to the path meanwhile (DR-9).
	img, err := openSelf(self, me.SID)
	if err != nil {
		return err
	}
	defer img.Close() //nolint:errcheck // read-only
	if err := winsec.EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	// a running install holds the binary open; stop it before replacing it
	stopInstalled()
	if err := copyBinary(img, self, l.Exe()); err != nil {
		return fmt.Errorf("copying the program: %w", err)
	}
	if err := makeFolders(l.DataRoot, me.SID); err != nil {
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

// sidTrustedInstaller owns Windows' own files.
const sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// openSelf refuses to install from a folder that another account could
// change, then opens the program so that no one can replace or rename it
// until setup ends (no write or delete sharing). Setup runs as an
// administrator and copies itself into Program Files to run as three
// services, so a file another user swapped in at that path would be
// installed in its place (DR-9). Accepted writers: the person running setup,
// Administrators, SYSTEM, TrustedInstaller, and the owner placeholders
// CREATOR OWNER and OWNER RIGHTS.
func openSelf(self, user string) (*os.File, error) {
	allowed := []string{winsec.SIDSystem, winsec.SIDAdministrators, user, sidTrustedInstaller, "S-1-3-0", "S-1-3-4"}
	for _, p := range []string{filepath.Dir(self), self} {
		if err := winsec.CheckWriters(p, allowed...); err != nil {
			return nil, fmt.Errorf("refusing to install from %s, because another account could replace the program there (%w); "+
				"copy soireehost.exe to a folder only you and administrators can change, such as your Downloads folder, and run setup from there",
				filepath.Dir(self), err)
		}
	}
	p, err := windows.UTF16PtrFromString(self)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", self, err)
	}
	return os.NewFile(uintptr(h), self), nil
}

// copyBinary copies the program open as in (found at src) to dst, unless
// src is dst.
func copyBinary(in *os.File, src, dst string) error {
	if a, err := filepath.Abs(src); err == nil && strings.EqualFold(a, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- Program Files permissions are inherited from Windows (Administrators write, Users read)
		return err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
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
func makeFolders(root, caller string) error {
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
	// Whether the root already exists is decided by creating it: a separate
	// check and create would leave a gap in which a standard user could
	// create it first (DR-8). An existing root, and everything inside it,
	// must belong to Administrators, SYSTEM or a SoiréeHost service.
	if err := winsec.CreateFolderSDDL(root, steps[0].sddl); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("%s: %w", root, err)
		}
		if err := checkDataRoot(root); err != nil {
			return err
		}
		// lock the root first, so nothing new can be planted while the
		// walk below runs
		if err := winsec.ForceSDDL(root, steps[0].sddl); err != nil {
			return fmt.Errorf("%s: %w", root, err)
		}
		if err := checkContents(root, caller, sup, web, tun); err != nil {
			return err
		}
	} else {
		steps = steps[1:] // the root is steps[0]
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

// checkContents refuses an existing data root that holds a link, junction or
// hard-linked file, or anything owned by an account other than
// Administrators, SYSTEM, the administrator running setup, or a SoiréeHost
// service. Re-permissioning sets only
// the folders' own descriptors, so anything a standard user planted inside
// before setup ran (a folder that lets everyone write, a config, an audit
// log) would otherwise survive the install (DR-8). The walk opens every
// entry through its parent's handle, so it cannot be redirected while it
// runs.
func checkContents(root string, services ...string) error {
	allowed := append([]string{winsec.SIDAdministrators, winsec.SIDSystem}, services...)
	return winsec.WalkTree(root, func(e winsec.TreeEntry) error {
		name := filepath.Join(root, e.Rel)
		if e.IsLink() || (!e.IsDir() && e.Links > 1) {
			return fmt.Errorf("refusing to install: %s is a link; delete %s and run setup again", name, root)
		}
		sd, err := windows.GetSecurityInfo(e.Handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("reading the owner of %s: %w", name, err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil {
			return fmt.Errorf("%s has no owner", name)
		}
		if !slices.Contains(allowed, owner.String()) {
			return fmt.Errorf("refusing to install: %s was created by another account (%s) and may have been planted; "+
				"check it, delete it if you do not recognise it, and run setup again", name, owner)
		}
		return nil
	})
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
	// The file is written with an explicit owner and descriptor, so it never
	// depends on the elevated token's default owner (which is the user's own
	// account on a full administrator token) or on an earlier file's.
	p := supervisor.Paths{Root: root}.ControlUsersFile()
	sup := winsec.ServiceSID(winsec.SupervisorService)
	sddl := "O:" + winsec.SIDAdministrators + "D:P(A;;FA;;;" + winsec.SIDSystem + ")(A;;FA;;;" + winsec.SIDAdministrators + ")(A;;FR;;;" + sup + ")"
	return winsec.WriteFileSDDL(p, sddl, b)
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
	// SeDebugPrivilege lets stopAndWait open each service's process
	_ = winsec.EnablePrivileges("SeDebugPrivilege")
	var errs []error
	allStopped := true
	// Record every service's process before stopping anything: the
	// supervisor stops the workers itself, and a worker that then reports
	// "stopped" shows no process id even if its process is still running.
	var pids []uint32
	for _, spec := range services {
		if s, err := m.OpenService(spec.name); err == nil {
			if st, err := s.Query(); err == nil && st.ProcessId != 0 {
				pids = append(pids, st.ProcessId)
			}
			_ = s.Close()
		}
	}
	// supervisor first: it stops both workers itself
	for _, spec := range services {
		s, err := m.OpenService(spec.name)
		if err != nil {
			continue
		}
		if !stopAndWait(s) {
			allStopped = false
		}
		if err := s.Delete(); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", spec.name, err))
		}
		_ = s.Close()
		_ = eventlog.Remove(spec.name)
	}
	for _, pid := range pids {
		if !processExited(pid, 10*time.Second) {
			allStopped = false
		}
	}
	if self, err := os.Executable(); err == nil && strings.EqualFold(filepath.Dir(self), l.ProgramDir) {
		errs = append(errs, errors.New("run uninstall from a copy outside the program folder to remove it (self-removal comes in Phase 6)"))
	} else if err := os.RemoveAll(l.ProgramDir); err != nil {
		errs = append(errs, err)
	}
	if purge && !allStopped {
		// A service process still running could change the data folder while
		// it is taken over, so the purge waits for a restart (DR-7).
		errs = append(errs, errors.New("a SoiréeHost service did not stop, so the data folder was kept; restart the PC and run uninstall --purge again"))
	} else if purge {
		if err := takeBack(l.DataRoot); err != nil {
			errs = append(errs, err)
		} else if err := os.RemoveAll(l.DataRoot); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// stopAndWait stops a service and reports whether its process has exited.
// A service can report "stopped" and keep running, so the process itself is
// waited on.
func stopAndWait(s *mgr.Service) bool {
	st, err := s.Query()
	if err != nil {
		return false
	}
	pid := st.ProcessId
	if st.State != svc.Stopped {
		if st, err = s.Control(svc.Stop); err != nil {
			if st, err = s.Query(); err != nil {
				return false
			}
		}
		deadline := time.Now().Add(20 * time.Second)
		for st.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return false
			}
		}
		if st.State != svc.Stopped {
			return false
		}
	}
	return processExited(pid, 10*time.Second)
}

// processExited waits up to wait for process pid to end. A pid that no
// longer exists counts as ended.
func processExited(pid uint32, wait time.Duration) bool {
	if pid == 0 {
		return true
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h)                                             //nolint:errcheck // nothing to do on failure
	ev, err := windows.WaitForSingleObject(h, uint32(wait/time.Millisecond)) // #nosec G115 -- a few seconds
	return err == nil && ev == windows.WAIT_OBJECT_0
}

// takeBack makes Administrators owner of root and everything under it, with
// full control, so an elevated uninstall can delete folders that only the
// services could open.
func takeBack(root string) error {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := winsec.EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + winsec.SIDAdministrators + "D:P(A;OICI;FA;;;" + winsec.SIDAdministrators + ")")
	if err != nil {
		return err
	}
	// WalkTree opens each entry through its parent's handle and never enters
	// a link, so a junction swapped in during the walk is taken over as a
	// link object and its target is never touched (DR-7). A file with
	// several hard links is not re-permissioned (that would change its other
	// ends too); RemoveAll unlinks it through the folder, which
	// Administrators then control.
	return winsec.WalkTree(root, func(e winsec.TreeEntry) error {
		if !e.IsDir() && e.Links > 1 {
			return nil
		}
		if err := windows.SetKernelObjectSecurity(e.Handle, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, sd); err != nil {
			return fmt.Errorf("taking ownership of %s: %w", filepath.Join(root, e.Rel), err)
		}
		return nil
	})
}
