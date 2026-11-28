// Package sdparse reads an SDDL file or folder descriptor the one way every
// applier in SoiréeHost reads it (review finding SE-04): winsec.CreateFolderSDDL,
// winsec.ForceSDDL, winsec.ForceSDDLUnlessLinked and the test fixture
// winsectest.SetFolderSDDL. It is its own package so that both winsec and
// winsectest, which the tests of winsec import, can use it.
package sdparse

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// Descriptor is a parsed file or folder descriptor.
type Descriptor struct {
	SD    *windows.SECURITY_DESCRIPTOR
	DACL  *windows.ACL
	Owner *windows.SID // nil when the SDDL names no owner
}

// Parse parses sddl. It requires a DACL that is present
// ("D:"), not NULL (no "NO_ACCESS_CONTROL") and protected ("D:P"), so
// nothing is inherited from the parent. An owner ("O:") is optional. A group
// ("G:") or a SACL ("S:") is refused: no applier writes them, so accepting
// them would let the text claim more than is applied.
func Parse(sddl string) (Descriptor, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return Descriptor{}, fmt.Errorf("security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		return Descriptor{}, errors.New("security descriptor has no access list (D:)")
	case err != nil:
		return Descriptor{}, fmt.Errorf("security descriptor access list: %w", err)
	case dacl == nil:
		return Descriptor{}, errors.New("security descriptor has a NULL access list, which lets everyone in")
	}
	control, _, err := sd.Control()
	if err != nil {
		return Descriptor{}, fmt.Errorf("security descriptor control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return Descriptor{}, errors.New("security descriptor access list is not protected (D:P)")
	}
	if g, _, err := sd.Group(); err != nil || g != nil {
		return Descriptor{}, errors.New("security descriptor names a group (G:), which is never applied")
	}
	if _, _, err := sd.SACL(); !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return Descriptor{}, errors.New("security descriptor has a system access list (S:), which is never applied")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return Descriptor{}, fmt.Errorf("security descriptor owner: %w", err)
	}
	return Descriptor{SD: sd, DACL: dacl, Owner: owner}, nil
}
