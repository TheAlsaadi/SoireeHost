package sitecheck

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// Locations are the folders that may never be published, or contain a
// published folder, or sit inside one (S-11).
type Locations struct {
	// Windows is the Windows folder, for example C:\Windows.
	Windows string
	// ProgramFiles lists C:\Program Files and C:\Program Files (x86).
	ProgramFiles []string
	// ProgramData is %ProgramData%. It holds SoiréeHost's own config and
	// secrets and other services' private data (OpenSSH host keys, for
	// example), so none of it may be published.
	ProgramData string
	// UserProfiles is the folder holding user profiles, for example C:\Users.
	// It and every profile root directly inside it are refused; folders
	// deeper inside a profile are allowed (except AppData and .ssh).
	UserProfiles string
}

// DefaultLocations reads the folders from Windows.
func DefaultLocations() (Locations, error) {
	get := func(id *windows.KNOWNFOLDERID) (string, error) {
		p, err := windows.KnownFolderPath(id, 0)
		if err != nil {
			return "", fmt.Errorf("reading known folder: %w", err)
		}
		return canonicalOrClean(p), nil
	}
	var loc Locations
	var err error
	if loc.Windows, err = get(windows.FOLDERID_Windows); err != nil {
		return Locations{}, err
	}
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		p, err := get(id)
		if err != nil {
			return Locations{}, err
		}
		loc.ProgramFiles = append(loc.ProgramFiles, p)
	}
	if loc.ProgramData, err = get(windows.FOLDERID_ProgramData); err != nil {
		return Locations{}, err
	}
	if loc.UserProfiles, err = get(windows.FOLDERID_UserProfiles); err != nil {
		return Locations{}, err
	}
	return loc, nil
}

func canonicalOrClean(p string) string {
	if c, err := Canonical(p); err == nil {
		return c
	}
	return filepath.Clean(p)
}

// CheckRoot resolves a static root to its real location (following junctions
// and symbolic links, expanding 8.3 short names, fixing letter case) and
// checks that location against every S-11 rule. It returns the canonical
// path, which is what the config should store.
func CheckRoot(root string, loc Locations) (string, error) {
	if err := config.ValidateRootSyntax(root); err != nil {
		return "", err
	}
	h, err := openDir(root)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only handle; nothing to report
	canon, err := finalPath(h)
	if err != nil {
		return "", err
	}
	if err := checkCanonical(canon, loc); err != nil {
		return "", err
	}
	return canon, nil
}

// OpenRoot opens a static root for serving. It resolves and checks the folder
// as CheckRoot does, opens it as an os.Root (which refuses any path or link
// that leaves the folder), and confirms that the os.Root is the very folder
// that was checked, so swapping the folder for a junction between the check
// and the open is caught.
func OpenRoot(root string, loc Locations) (*os.Root, error) {
	if err := config.ValidateRootSyntax(root); err != nil {
		return nil, err
	}
	h, err := openDir(root)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only handle; nothing to report
	canon, err := finalPath(h)
	if err != nil {
		return nil, err
	}
	if err := checkCanonical(canon, loc); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(canon)
	if err != nil {
		return nil, fmt.Errorf("opening site folder: %w", err)
	}
	same, err := sameAsHandle(r, h)
	if err != nil || !same {
		_ = r.Close()
		return nil, errors.New("the site folder changed while it was being opened; try again")
	}
	return r, nil
}

// Canonical returns the real path of an existing folder.
func Canonical(p string) (string, error) {
	h, err := openDir(p)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only handle; nothing to report
	return finalPath(h)
}

func openDir(p string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return windows.InvalidHandle, errors.New("not a valid path")
	}
	h, err := windows.CreateFile(name,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("cannot open the folder: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, fmt.Errorf("cannot read the folder: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, errors.New("not a folder")
	}
	return h, nil
}

func finalPath(h windows.Handle) (string, error) {
	const size = windows.MAX_LONG_PATH
	buf := make([]uint16, size)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], size, fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the folder: %w", err)
	}
	if int(n) >= len(buf) {
		return "", errors.New("folder path too long")
	}
	p := windows.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return "", errors.New("network folders are not supported; choose a folder on a local drive")
	case strings.HasPrefix(p, `\\?\`):
		p = p[len(`\\?\`):]
	default:
		return "", errors.New("the folder is not on a lettered local drive")
	}
	return p, nil
}

func sameAsHandle(r *os.Root, h windows.Handle) (bool, error) {
	f, err := r.Open(".")
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only
	var a, b windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &a); err != nil {
		return false, err
	}
	if err := windows.GetFileInformationByHandle(h, &b); err != nil {
		return false, err
	}
	return a.VolumeSerialNumber == b.VolumeSerialNumber &&
		a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow, nil
}

// checkCanonical applies the location rules to a resolved path.
func checkCanonical(canon string, loc Locations) error {
	// the resolved path must still pass the syntax rules (drive root, AppData,
	// .ssh, reserved names), since a junction can point anywhere
	if err := config.ValidateRootSyntax(canon); err != nil {
		return fmt.Errorf("the folder resolves to %s: %w", canon, err)
	}
	refuse := func(what, p string) error {
		if p == "" {
			return nil
		}
		if equalPath(canon, p) || within(canon, p) || within(p, canon) {
			return fmt.Errorf("%s cannot be published, and neither can folders inside it or folders that contain it", what)
		}
		return nil
	}
	if err := refuse("The Windows folder", loc.Windows); err != nil {
		return err
	}
	for _, pf := range loc.ProgramFiles {
		if err := refuse("Program Files", pf); err != nil {
			return err
		}
	}
	if err := refuse("ProgramData, which holds service settings and keys,", loc.ProgramData); err != nil {
		return err
	}
	if up := loc.UserProfiles; up != "" {
		if equalPath(canon, up) || within(up, canon) {
			return errors.New("the Users folder cannot be published")
		}
		if within(canon, up) && !strings.Contains(canon[len(up)+1:], `\`) {
			return errors.New("a whole user profile cannot be published; choose a folder inside it, such as Documents\\site")
		}
	}
	return nil
}

func equalPath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }

// within reports whether p is strictly inside dir.
func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if len(p) <= len(dir) || !strings.EqualFold(p[:len(dir)], dir) {
		return false
	}
	return p[len(dir)] == '\\' || strings.HasSuffix(dir, `\`)
}

// Flags for GetFinalPathNameByHandle (fileapi.h); x/sys/windows does not
// define them.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)
