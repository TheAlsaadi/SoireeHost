package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// openAppendOnly opens (creating if needed) path asking for nothing but
// FILE_APPEND_DATA and SYNCHRONIZE. os.OpenFile with O_APPEND also asks for
// write-attributes, write-extended-attributes and read-permissions, which
// the audit folder's append-only entry (winsec.AuditFolderSDDL) rightly does
// not grant, so it is refused on every open after the file is created.
func openAppendOnly(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
