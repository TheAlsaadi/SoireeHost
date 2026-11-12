// Package fsutil has small file helpers shared by the stores.
package fsutil

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// WriteAtomic writes data to a temporary file in the same folder as path,
// flushes it to disk, and moves it over path with MOVEFILE_WRITE_THROUGH. A
// crash at any point leaves either the old file or the new one, never a mix.
// The new file takes the folder's inheritable permissions.
func WriteAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) //nolint:errcheck // gone after a successful move
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
