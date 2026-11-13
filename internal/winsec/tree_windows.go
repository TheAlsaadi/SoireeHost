package winsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TreeEntry is one object found by WalkTree.
type TreeEntry struct {
	// Handle is open on the object itself (never on a link's target) with
	// READ_CONTROL, WRITE_DAC and WRITE_OWNER, so a visitor can read or set
	// its descriptor on the very object that was listed.
	Handle windows.Handle
	// Rel is the path relative to the root; "" for the root itself.
	Rel string
	// Attrs are the object's file attributes.
	Attrs uint32
	// Links is the number of hard links to the object.
	Links uint32
}

// IsDir reports whether the entry is a folder.
func (e TreeEntry) IsDir() bool { return e.Attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 }

// IsLink reports whether the entry is a reparse point: a junction, mount
// point or symbolic link. WalkTree never enters one.
func (e TreeEntry) IsLink() bool { return e.Attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 }

const (
	// treeAccess lets a visitor read and replace the descriptor, and lets
	// WalkTree list a folder, whatever the object's own access list says:
	// with backup intent, SeBackupPrivilege grants the read rights and
	// SeRestorePrivilege the write rights.
	treeAccess = windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	treeShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

	// FILE_INFO_BY_HANDLE_CLASS values for listing a folder
	fileFullDirectoryInfo        = 14
	fileFullDirectoryRestartInfo = 15
)

// WalkTree visits root and everything under it, top-down. Every object is
// opened relative to its parent's open handle, without following reparse
// points, and its folder listing is read through that same handle. Renaming a
// folder or swapping in a junction while the walk runs therefore cannot send
// it outside the tree (DR-7): a path is never resolved twice. Reparse points
// are visited but never entered. visit runs before a folder is listed, so it
// may first change the folder's descriptor through e.Handle.
//
// The caller must have SeBackupPrivilege and SeRestorePrivilege enabled. The
// handle in a TreeEntry is closed when visit returns.
func WalkTree(root string, visit func(TreeEntry) error) error {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, treeAccess, treeShare, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("opening %s: %w", root, err)
	}
	return walkHandle(h, "", root, visit)
}

func walkHandle(h windows.Handle, rel, root string, visit func(TreeEntry) error) error {
	defer windows.CloseHandle(h) //nolint:errcheck // nothing to do on failure
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Join(root, rel), err)
	}
	e := TreeEntry{Handle: h, Rel: rel, Attrs: info.FileAttributes, Links: info.NumberOfLinks}
	if err := visit(e); err != nil {
		return err
	}
	if !e.IsDir() || e.IsLink() {
		return nil
	}
	names, err := listDir(h)
	if err != nil {
		return fmt.Errorf("listing %s: %w", filepath.Join(root, rel), err)
	}
	for _, n := range names {
		child, err := openChild(h, n)
		if err != nil {
			return fmt.Errorf("opening %s: %w", filepath.Join(root, rel, n), err)
		}
		if err := walkHandle(child, filepath.Join(rel, n), root, visit); err != nil {
			return err
		}
	}
	return nil
}

// openChild opens name inside the folder open as parent, never following a
// reparse point.
func openChild(parent windows.Handle, name string) (windows.Handle, error) {
	us, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: us}
	oa.Length = uint32(unsafe.Sizeof(oa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, treeAccess, &oa, &iosb, nil, 0, treeShare, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}

// listDir returns the names in the folder open as h, without "." and "..".
// Entries are FILE_FULL_DIR_INFO records, read field by field from the
// buffer: NextEntryOffset at 0, FileNameLength at 60, FileName at 68.
func listDir(h windows.Handle) ([]string, error) {
	buf := make([]byte, 64*1024)
	var names []string
	class := uint32(fileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(h, class, &buf[0], uint32(len(buf))) // #nosec G115 -- 64 KiB
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		class = fileFullDirectoryInfo
		for off := 0; ; {
			if off+68 > len(buf) {
				return nil, errors.New("malformed folder listing")
			}
			next := int(binary.LittleEndian.Uint32(buf[off:]))
			nameLen := int(binary.LittleEndian.Uint32(buf[off+60:]))
			if nameLen%2 != 0 || off+68+nameLen > len(buf) {
				return nil, errors.New("malformed folder listing")
			}
			u := make([]uint16, nameLen/2)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(buf[off+68+2*i:])
			}
			if n := windows.UTF16ToString(u); n != "." && n != ".." {
				names = append(names, n)
			}
			if next == 0 {
				break
			}
			off += next
		}
	}
}
