// Package winsectest holds Windows security fixtures for tests. Only _test.go
// files may import it; TestImportedOnlyFromTests fails otherwise (SE-03).
package winsectest

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec/sdparse"
)

// SetFolderSDDL creates path if needed and applies an SDDL security
// descriptor (owner if present, and a protected DACL) to it. An elevated
// administrator's new folders are owned by Administrators, so name the owner
// when it matters. The SDDL is read as the product reads it
// (sdparse.Parse, review finding SE-04): it must have a protected,
// non-NULL DACL and no group or SACL.
//
// It is a test fixture and must never be used by the product: the new folder
// carries its parent's permissions for a moment, links and junctions are
// followed, and the permissions propagate down the tree. Product code uses
// winsec.CreateFolderSDDL or winsec.ForceSDDL.
func SetFolderSDDL(path, sddl string) error {
	d, err := sdparse.Parse(sddl)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if d.Owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, d.Owner, nil, d.DACL, nil)
}
