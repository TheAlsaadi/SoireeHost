package winsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Dir is a folder open by handle. Every name inside it is opened relative to
// that handle and never through a reparse point, so a folder that a service
// swaps for a junction, or empties and turns into a mount point, after it was
// opened cannot send an elevated caller anywhere else (DR-7; security review
// of 20 Nov 2026). Use it whenever elevated code reads or writes a folder that
// a service account can change.
type Dir struct {
	h    windows.Handle
	path string // for messages only; never resolved again
}

const (
	// FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY (winnt.h), which x/sys does
	// not name: the folder rights behind FILE_WRITE_DATA and
	// FILE_APPEND_DATA
	fileAddFile         = 0x0002
	fileAddSubdirectory = 0x0004

	dirAccess = windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | fileAddFile |
		fileAddSubdirectory | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	dirShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
)

// errLink is returned for a name that is a link or a file with several
// hard links: its content belongs, or may belong, somewhere else.
var errLink = errors.New("is a link, not a plain file or folder")

// OpenDir opens the folder at path, refusing it if the last part of the
// path is a reparse point. The caller should know that the folders above it
// cannot be changed by the account it guards against.
func OpenDir(path string) (*Dir, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, dirAccess, dirShare, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return checkedDir(h, path)
}

func checkedDir(h windows.Handle, path string) (*Dir, error) {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	switch {
	case fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%s %w", path, errLink)
	case fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is not a folder", path)
	}
	return &Dir{h: h, path: path}, nil
}

// Close closes the folder.
func (d *Dir) Close() error { return windows.CloseHandle(d.h) }

// Path is the path the folder was opened at, for messages.
func (d *Dir) Path() string { return d.path }

// Names lists the folder, without "." and "..".
func (d *Dir) Names() ([]string, error) { return listDir(d.h) }

// validName refuses anything but one plain path element: a name with a
// separator would be resolved below the handle, through whatever is there.
func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return fmt.Errorf("%q is not a file name", name)
	}
	return nil
}

// openAt opens name relative to d, never following a reparse point.
func (d *Dir) openAt(name string, access uint32, share uint32, disposition, options uint32) (windows.Handle, error) {
	if err := validName(name); err != nil {
		return 0, err
	}
	us, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: d.h, ObjectName: us}
	oa.Length = uint32(unsafe.Sizeof(oa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", filepath.Join(d.path, name), err)
	}
	return h, nil
}

// Sub opens the folder name inside d, creating it if create is set. A link
// is refused.
func (d *Dir) Sub(name string, create bool) (*Dir, error) {
	disp := uint32(windows.FILE_OPEN)
	if create {
		disp = windows.FILE_OPEN_IF
	}
	h, err := d.openAt(name, dirAccess, dirShare, disp, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return nil, err
	}
	return checkedDir(h, filepath.Join(d.path, name))
}

// plainFile refuses a reparse point, a folder, or a file with more than one
// hard link: writing or reading through another link would reach a file
// elsewhere on the volume.
func plainFile(h windows.Handle, path string) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if fi.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || fi.NumberOfLinks != 1 {
		return fmt.Errorf("%s %w", path, errLink)
	}
	return nil
}

// ReadFile reads the plain file name in d, at most maxBytes of it. It does
// not use backup semantics, so the file's own access list applies.
func (d *Dir) ReadFile(name string, maxBytes int64) ([]byte, error) {
	h, err := d.openAt(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), filepath.Join(d.path, name))
	defer f.Close() //nolint:errcheck // read-only
	if err := plainFile(h, f.Name()); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s is too large", f.Name())
	}
	return b, nil
}

// Remove deletes name from d. A link is removed itself, never its target.
// A name that does not exist is not an error.
func (d *Dir) Remove(name string) error {
	h, err := d.openAt(name, windows.DELETE, dirShare, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_DELETE_ON_CLOSE)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

// WriteFile writes data as a new plain file name in d. Whatever had that
// name is deleted first and the file is created afresh, so an existing hard
// link or reparse point is never written through. The new file takes the
// folder's inheritable permissions (convention rule 13).
func (d *Dir) WriteFile(name string, data []byte) error {
	if err := d.Remove(name); err != nil {
		return err
	}
	h, err := d.openAt(name, windows.GENERIC_WRITE, 0, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_WRITE_THROUGH)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), filepath.Join(d.path, name))
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
