// Package winsectest holds Windows security fixtures for tests. Only _test.go
// files may import it; TestImportedOnlyFromTests fails otherwise (SE-03).
package winsectest

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// SetFolderSDDL creates path if needed and applies an SDDL security
// descriptor (owner if present, and a protected DACL) to it. An elevated
// administrator's new folders are owned by Administrators, so name the owner
// when it matters.
//
// It is a test fixture and must never be used by the product: the new folder
// carries its parent's permissions for a moment, links and junctions are
// followed, and the permissions propagate down the tree. Product code uses
// winsec.CreateFolderSDDL or winsec.ForceSDDL.
func SetFolderSDDL(path, sddl string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("security descriptor owner: %w", err)
	}
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}
