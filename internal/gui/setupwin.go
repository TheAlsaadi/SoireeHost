package gui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/version"
)

// The control panel starts setup through the Windows prompt and only with
// fixed arguments (ADR-0010). The UI names an action from a closed set; it
// never passes a path or a command line.

// Setup actions the UI may ask for.
const (
	ActionInstall        = "install"         // this copy installs itself, or upgrades an older install
	ActionRepair         = "repair"          // the installed program repairs the install
	ActionApplyUpdate    = "apply-update"    // the installed program installs the staged update
	ActionUninstall      = "uninstall"       // keeps settings, the token and logs
	ActionUninstallPurge = "uninstall-purge" // removes them too
)

// Setup modes the window opens in.
const (
	ModeInstalled    = "installed"     // the control panel of an installed SoiréeHost
	ModeNotInstalled = "not_installed" // nothing installed: the install window
	ModeOtherCopy    = "other_copy"    // installed, but this is another copy (Downloads)
	ModeUninstall    = "uninstall"     // opened from Settings > Apps
)

// SetupState tells the UI which window to show.
type SetupState struct {
	Mode             string `json:"mode"`
	InstalledVersion string `json:"installed_version"`
	ThisVersion      string `json:"this_version"`
	// Newer: this copy is newer than the installed version, so it can
	// upgrade it.
	Newer bool `json:"newer"`
}

// SetupResult is how a setup run ended. Code is setup's closed-set exit
// code (internal/setup.Code); Cancelled means the Windows prompt was
// declined and nothing ran.
type SetupResult struct {
	Code      int  `json:"code"`
	Cancelled bool `json:"cancelled"`
}

// uninstallKey is the Settings > Apps entry setup writes.
const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SoireeHost`

// setupHost is what the setup bindings need from the system, so tests can
// stand in for the service manager, the registry and the Windows prompt.
type setupHost interface {
	serviceInstalled() bool
	installedVersion() string
	installedExe() string
	thisExe() (string, error)
	runElevated(exe, args string) (code int, cancelled bool, err error)
	quit()
}

// setupState decides the window's mode.
func setupState(h setupHost, uninstall bool) SetupState {
	s := SetupState{ThisVersion: version.Current(), InstalledVersion: h.installedVersion()}
	// no version known (nothing installed, or an install from before the
	// Apps entry existed): this copy may install over it
	if c, err := version.Compare(s.ThisVersion, s.InstalledVersion); s.InstalledVersion == "" || (err == nil && c > 0) {
		s.Newer = true
	}
	self, err := h.thisExe()
	running := err == nil && strings.EqualFold(filepath.Clean(self), filepath.Clean(h.installedExe()))
	switch {
	case uninstall:
		s.Mode = ModeUninstall
	case !h.serviceInstalled():
		s.Mode = ModeNotInstalled
	case !running:
		s.Mode = ModeOtherCopy
	default:
		s.Mode = ModeInstalled
	}
	return s
}

// setupCommand maps an action to the program and fixed arguments it runs.
// Install runs this copy; everything else runs the installed program.
func setupCommand(h setupHost, action string) (exe, args string, err error) {
	switch action {
	case ActionInstall:
		exe, err = h.thisExe()
		return exe, "setup install", err
	case ActionRepair:
		return h.installedExe(), "setup repair", nil
	case ActionApplyUpdate:
		return h.installedExe(), "setup apply-update", nil
	case ActionUninstall:
		return h.installedExe(), "setup uninstall", nil
	case ActionUninstallPurge:
		return h.installedExe(), "setup uninstall --purge", nil
	}
	return "", "", plainError(ipc.CodeInvalid, "Unknown setup action.")
}

// Setup is bound to the UI: the setup window's state and the one call that
// raises the Windows prompt.
type Setup struct {
	host      setupHost
	uninstall bool

	mu       sync.Mutex
	busy     bool
	relaunch bool // start the installed control panel when this one exits
}

// NewSetup returns the service. uninstall is the --uninstall option.
func NewSetup(h setupHost, uninstall bool) *Setup { return &Setup{host: h, uninstall: uninstall} }

// State is the window's mode and the versions involved.
func (s *Setup) State() SetupState { return setupState(s.host, s.uninstall) }

// Run raises the Windows prompt for one setup action and waits for it.
// After an install or an update this control panel exits and the installed
// one starts; after an uninstall it exits.
func (s *Setup) Run(action string) (SetupResult, error) {
	exe, args, err := setupCommand(s.host, action)
	if err != nil {
		return SetupResult{}, err
	}
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return SetupResult{}, plainError(ipc.CodeUnavailable, "Setup is already running.")
	}
	s.busy = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.busy = false; s.mu.Unlock() }()

	code, cancelled, err := s.host.runElevated(exe, args)
	if err != nil {
		return SetupResult{}, plainError(ipc.CodeUnavailable, "Could not start setup.")
	}
	res := SetupResult{Code: code, Cancelled: cancelled}
	if cancelled || code != 0 {
		return res, nil
	}
	switch action {
	case ActionInstall, ActionApplyUpdate:
		s.mu.Lock()
		s.relaunch = true
		s.mu.Unlock()
	}
	return res, nil
}

// OpenInstalled closes this copy and starts the installed control panel.
func (s *Setup) OpenInstalled() {
	s.mu.Lock()
	s.relaunch = true
	s.mu.Unlock()
	s.host.quit()
}

// Close closes the window and quits (after an uninstall, or from the
// install window).
func (s *Setup) Close() { s.host.quit() }

// afterExit runs when the window has closed: it starts the installed
// control panel, unelevated, if an install or update asked for that.
func (s *Setup) afterExit() {
	s.mu.Lock()
	again := s.relaunch
	s.mu.Unlock()
	if !again {
		return
	}
	exe := s.host.installedExe()
	if _, err := os.Stat(exe); err != nil {
		return
	}
	// a plain, unelevated start of the installed program with a fixed
	// argument; it opens its own window
	// #nosec G204 -- the installed program from the known folder, a fixed argument
	cmd := exec.Command(exe, "gui") //nolint:noctx // it outlives this exiting process
	_ = cmd.Start()
}

// systemHost is the real setupHost.
type systemHost struct{ quitApp func() }

func (systemHost) serviceInstalled() bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m) //nolint:errcheck // nothing to do on failure
	name, _ := windows.UTF16PtrFromString("SoireeHost")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	_ = windows.CloseServiceHandle(s)
	return true
}

func (systemHost) installedVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close() //nolint:errcheck // read-only
	v, _, err := k.GetStringValue("DisplayVersion")
	if err != nil || !version.Valid(v) {
		return ""
	}
	return v
}

// installedExe is %ProgramFiles%\SoireeHost\soireehost.exe, from the known
// folder, never from an environment variable the user could change.
func (systemHost) installedExe() string {
	loc, err := sitecheck.DefaultLocations()
	if err != nil || len(loc.ProgramFiles) == 0 {
		return ""
	}
	return filepath.Join(loc.ProgramFiles[0], "SoireeHost", "soireehost.exe")
}

func (systemHost) thisExe() (string, error) { return os.Executable() }

func (h systemHost) quit() {
	if h.quitApp != nil {
		h.quitApp()
	}
}

// ShellExecuteExW, which golang.org/x/sys/windows does not wrap, from
// System32 only (convention rule 9).
var (
	modShell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modShell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	size       uint32
	mask       uint32
	hwnd       windows.HWND
	verb       *uint16
	file       *uint16
	parameters *uint16
	directory  *uint16
	show       int32
	instApp    windows.Handle
	idList     uintptr
	class      *uint16
	keyClass   windows.Handle
	hotKey     uint32
	iconOrMon  windows.Handle
	process    windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	seeMaskFlagNoUI       = 0x00000400
	swShowNormal          = 1
)

// runElevated starts exe with args through the Windows prompt ("runas")
// and waits for it to exit.
func (systemHost) runElevated(exe, args string) (int, bool, error) {
	if exe == "" {
		return 0, false, errors.New("no program to run")
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, false, err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 0, false, err
	}
	info := shellExecuteInfo{
		mask: seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		verb: verb, file: file, parameters: params, show: swShowNormal,
	}
	info.size = uint32(unsafe.Sizeof(info)) // #nosec G103 G115 -- the size of a fixed Windows structure
	// #nosec G103 -- SHELLEXECUTEINFOW, as the API expects
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return 0, true, nil
		}
		return 0, false, err
	}
	if info.process == 0 {
		return 0, false, errors.New("setup did not start")
	}
	defer windows.CloseHandle(info.process) //nolint:errcheck // nothing to do on failure
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return 0, false, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return 0, false, err
	}
	return int(code), false, nil // #nosec G115 -- setup's exit codes are small
}

// watchUninstalled closes a control panel once SoiréeHost is uninstalled:
// the service is gone and the installed program has moved away. It also
// removes this user's sign-in entry, which uninstall cannot reach for other
// users (ADR-0010).
func watchUninstalled(ctx context.Context, h setupHost, l *Local, quit func()) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if h.serviceInstalled() {
			continue
		}
		if _, err := os.Stat(h.installedExe()); err == nil {
			continue
		}
		_ = l.SetStartAtSignIn(false)
		quit()
		return
	}
}
