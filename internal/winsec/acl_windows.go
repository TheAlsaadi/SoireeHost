package winsec

import (
	"fmt"
	"os"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeMask is every access right that lets a principal change a file or
// folder, its contents, or who may change it.
const writeMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	fileDeleteChild | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// CheckWriters fails unless every principal that the DACL of path lets write,
// delete or re-permission it is in allowed (SID strings), and the owner is in
// allowed (an owner can always rewrite the DACL). A missing (NULL) DACL, an
// allow entry of a kind this check does not understand, or an unreadable
// descriptor all fail (S-22).
func CheckWriters(path string, allowed ...string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading permissions of %s: %w", path, err)
	}
	return checkDescriptor(sd, path, allowed)
}

func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, path string, allowed []string) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s has no owner", path)
	}
	if !slices.Contains(allowed, owner.String()) {
		return fmt.Errorf("%s is owned by %s, which may change its permissions", path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no access list, so everyone may write to it", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading access list of %s: %w", path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%s has an access entry of type %d, which is not expected", path, ace.Header.AceType)
		}
		if uint32(ace.Mask)&writeMask == 0 {
			continue
		}
		// #nosec G103 -- the SID starts at SidStart inside the ACE, per the ACCESS_ALLOWED_ACE layout
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !slices.Contains(allowed, sid.String()) {
			return fmt.Errorf("%s can be changed by %s", path, sid)
		}
	}
	return nil
}

// SetFolderSDDL creates path if needed and applies an SDDL security
// descriptor (owner if present, and a protected DACL) to it.
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
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// fileDeleteChild is FILE_DELETE_CHILD (winnt.h), which x/sys/windows does
// not define.
const fileDeleteChild = 0x40

// EnablePrivileges turns on privileges the process token already holds (an
// elevated administrator holds SeRestorePrivilege and
// SeTakeOwnershipPrivilege, disabled by default).
func EnablePrivileges(names ...string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close() //nolint:errcheck // nothing to do on failure
	for _, n := range names {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(n)
		if err != nil {
			return err
		}
		if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			return err
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			return fmt.Errorf("enabling %s: %w", n, err)
		}
	}
	return nil
}

// ForceSDDL applies an SDDL descriptor (owner if given, and a protected DACL)
// to an existing file or folder through a backup-semantics handle, so that
// SeRestorePrivilege overrides whatever the current descriptor says. This is
// how the elevated setup role repairs folders whose descriptors lock even
// their owner out. The caller must have enabled SeRestorePrivilege.
func ForceSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, _ := sd.Owner()
	access := uint32(windows.WRITE_DAC)
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		access |= windows.WRITE_OWNER
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("opening %s to set permissions: %w", path, err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // nothing to do on failure
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

// Site folder access (ADR-0006, owner decision of 12 Nov 2026). When a site
// is added, the control panel, running as the folder's owner, grants:
//
//   - the web worker's account read and list access, inherited by
//     everything inside, so it can serve the files;
//   - the supervisor's account read-attributes and read-permissions on the
//     folder itself only, so it can resolve the folder's real path and
//     check that the worker can read it, without reading any file.
const (
	siteWorkerAccess     = "0x1200a9" // FILE_GENERIC_READ | FILE_TRAVERSE
	siteSupervisorAccess = "0x120080" // READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES
)

// GrantSiteAccess adds the two entries above to path's DACL, keeping what is
// already there. The caller must be allowed to change the folder's
// permissions (normally its owner).
func GrantSiteAccess(path, web, supervisor string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading permissions of %s: %w", path, err)
	}
	sddl := sd.String() + "(A;OICI;" + siteWorkerAccess + ";;;" + web + ")(A;;" + siteSupervisorAccess + ";;;" + supervisor + ")"
	nsd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := nsd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// readMask is the right that lets a principal list a folder or read a file.
const readMask = windows.FILE_LIST_DIRECTORY | windows.GENERIC_READ | windows.GENERIC_ALL

// GrantsRead reports whether path's DACL lets any of sids list and read it:
// an allow entry with read access for one of them, and no deny entry with
// read access for any of them. It reads only the DACL, so it answers for an
// account the caller cannot impersonate (the web worker's).
func GrantsRead(path string, sids ...string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil // a NULL DACL grants everything
	}
	allowed := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&readMask == 0 {
			continue
		}
		// #nosec G103 -- the SID starts at SidStart inside the ACE, per the ACE layout
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !slices.Contains(sids, sid) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			return false, nil
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowed = true
		}
	}
	return allowed, nil
}

// WorkerGroups are the SIDs whose read access the web worker's account
// inherits: its own, and the groups every service account's token carries.
func WorkerGroups(web string) []string {
	return []string{web, SIDEveryone, SIDAuthenticated, SIDUsers, "S-1-5-6"} // S-1-5-6: SERVICE
}

// CreateFolderSDDL creates a folder that has the given descriptor from the
// moment it exists, so there is no window in which it carries its parent's
// permissions. It fails if the folder already exists. Setting an owner other
// than the caller needs SeRestorePrivilege enabled.
func CreateFolderSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("security descriptor: %w", err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	return windows.CreateDirectory(p, &sa)
}

// ForceSDDLUnlessLinked is ForceSDDL, except that a file with more than one
// hard link is left alone and reported as skipped: re-permissioning it would
// also change the file at the link's other end, which may be anywhere on
// the volume.
func ForceSDDLUnlessLinked(path, sddl string) (skipped bool, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", path, err)
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	_ = windows.CloseHandle(h)
	if err != nil {
		return false, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks > 1 {
		return true, nil
	}
	return false, ForceSDDL(path, sddl)
}
