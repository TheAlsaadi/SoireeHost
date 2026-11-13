package winsec

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WriteFileSDDL replaces path with data, giving the new file exactly the
// descriptor sddl from the moment it exists. It writes a temporary file in
// the same folder with that descriptor, flushes it, and moves it over path.
// A moved file keeps its own descriptor, so an inherited one never applies.
func WriteFileSDDL(path, sddl string, data []byte) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("security descriptor: %w", err)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(b)
	p, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(h), tmp)
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(p, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}

// ReadOwnedFile reads at most max bytes of path, and only if the file's owner
// is wantOwner. The owner is read from the open handle, so it is the owner of
// the file that is read.
func ReadOwnedFile(path, wantOwner string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass fixed SoiréeHost paths
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, fmt.Errorf("%s has no owner", path)
	}
	if owner.String() != wantOwner {
		return nil, fmt.Errorf("%s is owned by %s, not %s", path, owner, wantOwner)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, errors.New(path + " is too large")
	}
	return b, nil
}
