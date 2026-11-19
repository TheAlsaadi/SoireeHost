package setup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// setupMutex lets one setup run at a time (ADR-0010). Only SYSTEM and
// Administrators may open it, and standard users lack the privilege to
// create objects in the Global namespace, so none can hold it to block
// setup.
const (
	setupMutex     = `Global\soireehost-setup`
	setupMutexSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

// lockSetup takes the setup mutex, or fails with CodeBusy.
func lockSetup() (unlock func(), err error) {
	h, existed, err := winsec.CreateMutexSDDL(setupMutex, setupMutexSDDL)
	if err != nil {
		return nil, fmt.Errorf("creating the setup lock: %w", err)
	}
	if existed {
		if o, err := winsec.OwnerOf(h); err != nil || (o != winsec.SIDAdministrators && o != winsec.SIDSystem) {
			_ = windows.CloseHandle(h)
			return nil, fail(CodeBusy, errors.New("the setup lock belongs to another account"))
		}
	}
	ev, err := windows.WaitForSingleObject(h, 0)
	if err != nil || (ev != windows.WAIT_OBJECT_0 && ev != windows.WAIT_ABANDONED) {
		_ = windows.CloseHandle(h)
		return nil, fail(CodeBusy, errors.New("another SoiréeHost setup is running; wait for it to finish"))
	}
	return func() {
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
	}, nil
}

// requireAdmin fails with CodeNotElevated unless setup runs elevated, and
// returns the caller's SID.
func requireAdmin() (string, error) {
	me, err := winsec.CurrentCaller()
	if err != nil {
		return "", err
	}
	if !me.Admin {
		return "", fail(CodeNotElevated, errors.New("setup must run from an elevated (administrator) prompt"))
	}
	return me.SID, nil
}

// requireInstalledCopy fails with CodeNotInstalled unless this process is
// the installed program: only the installed, already-trusted binary may
// repair or update an install (ADR-0010).
func requireInstalledCopy(l Layout) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(l.Exe())) {
		return fail(CodeNotInstalled, fmt.Errorf("run this from the installed program, %s", l.Exe()))
	}
	return nil
}

// installedVersion reads DisplayVersion from the Apps entry, or "" if there
// is none (nothing installed, or an install from before Phase 6).
func installedVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, UninstallKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close() //nolint:errcheck // read-only
	v, _, err := k.GetStringValue("DisplayVersion")
	if err != nil {
		return ""
	}
	return v
}

// writeAppsEntry writes the Settings > Apps entry (ADR-0010). The key
// inherits HKLM\SOFTWARE's permissions: only Administrators and SYSTEM may
// change it.
func writeAppsEntry(l Layout, ver string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, UninstallKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("writing the Apps entry: %w", err)
	}
	defer k.Close() //nolint:errcheck // values are written before
	for _, v := range appsEntry(l, ver, folderSizeKB(l.ProgramDir)) {
		if v.IsDword {
			err = k.SetDWordValue(v.Name, v.Dword)
		} else {
			err = k.SetStringValue(v.Name, v.Text)
		}
		if err != nil {
			return fmt.Errorf("writing the Apps entry: %w", err)
		}
	}
	return nil
}

// removeAppsEntry deletes the Apps entry; a missing one is fine.
func removeAppsEntry() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, UninstallKey)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		// DeleteKey has no WOW64 flag; on 64-bit Windows a 64-bit process
		// already sees the 64-bit view
		return fmt.Errorf("removing the Apps entry: %w", err)
	}
	return nil
}

// folderSizeKB is the size of the files under dir, in KB, for the Apps
// entry's EstimatedSize.
func folderSizeKB(dir string) uint32 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	kb := total / 1024
	if kb > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(kb) // #nosec G115 -- bounded just above
}

// The sign-in entry is the same per-user Run value the control panel
// writes (internal/gui, owner decision of 15 Nov 2026).
const (
	runKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue = "SoireeHost"
)

// runCommand is the sign-in entry's command for the installed program.
func runCommand(l Layout) string { return quote(l.Exe()) + " gui --tray" }

// writeRunEntry sets the installing user's sign-in entry. The elevated
// token's user is the installing user (ADR-0006 notes the over-the-shoulder
// case).
func writeRunEntry(l Layout) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close() //nolint:errcheck // closed after the write
	return k.SetStringValue(runValue, runCommand(l))
}

// removeRunEntry removes the sign-in entry of the user running uninstall;
// other users' entries cannot be reached and are left dangling (ADR-0010).
func removeRunEntry() {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close() //nolint:errcheck // closed after the delete
	_ = k.DeleteValue(runValue)
}
