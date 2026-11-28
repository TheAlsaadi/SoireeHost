package winsec

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/winsec/sdparse"
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
//
// path itself must not be a link, junction or mount point: its own
// descriptor is read without following it (review finding SE-09). Every
// folder above it is checked too (checkParents), since an account that can
// rename or delete a folder on the way could replace path with one of its
// own.
func CheckWriters(path string, allowed ...string) error {
	return CheckOwnerAndWriters(path, allowed, allowed)
}

// CheckOwnerAndWriters is CheckWriters with its own list of accepted owners:
// the owner must be in owners, and every principal the DACL lets change path
// must be in writers. The folders above path are checked against owners.
func CheckOwnerAndWriters(path string, owners, writers []string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sd, err := securityNoFollow(abs)
	if err != nil {
		return err
	}
	if err := checkDescriptor(sd, abs, owners, writers); err != nil {
		return err
	}
	return checkParents(abs, owners)
}

// ErrLinkInPath is returned by CheckWriters and CheckOwnerAndWriters when the
// path, or a folder above it, is a link, junction or mount point.
var ErrLinkInPath = errors.New("is a link, junction or mount point")

// securityNoFollow reads the owner and DACL of path through a handle that
// does not follow a reparse point, and refuses path if it is a link,
// junction or mount point.
func securityNoFollow(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("reading permissions of %s: %w", path, err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only handle
	fi, err := attributeTagInfo(h)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if isLink(fi) {
		return nil, fmt.Errorf("%s %w", path, ErrLinkInPath)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("reading permissions of %s: %w", path, err)
	}
	return sd, nil
}

// replaceMask is every right on a folder that lets a principal take away
// what is inside it, or the folder itself, and put something else there:
// delete or rename the folder, delete or rename its entries, or change who
// may do either.
const replaceMask = windows.DELETE | fileDeleteChild | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// checkParents checks every folder above path, up to the volume root (SE-09).
// Each must not be a link, junction or mount point, must be owned by SYSTEM,
// Administrators, TrustedInstaller or one of owners, and must give no one
// else a right in replaceMask. Rights only to add entries (such as the right
// of Users to create folders in %ProgramData%) do not let anyone replace an
// existing one, and are allowed. On a volume root, which cannot be renamed
// or deleted, plain delete is allowed too (a drive formatted by Windows
// gives Authenticated Users modify there).
func checkParents(path string, owners []string) error {
	trusted := append([]string{SIDSystem, SIDAdministrators, SIDTrustedInstaller}, owners...)
	for child, dir := path, filepath.Dir(path); dir != child; child, dir = dir, filepath.Dir(dir) {
		sd, err := securityNoFollow(dir)
		if err != nil {
			return fmt.Errorf("checking the folders that hold %s: %w", path, err)
		}
		if err := checkParent(sd, dir, trusted); err != nil {
			return fmt.Errorf("%w, so %s could be replaced", err, path)
		}
	}
	return nil
}

func checkParent(sd *windows.SECURITY_DESCRIPTOR, dir string, trusted []string) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s has no owner", dir)
	}
	if !slices.Contains(trusted, owner.String()) {
		return fmt.Errorf("%s is owned by %s", dir, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no access list", dir)
	}
	mask := uint32(replaceMask)
	if filepath.Dir(dir) == dir {
		mask &^= windows.DELETE
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading access list of %s: %w", dir, err)
		}
		// an inherit-only entry applies to what is created inside, not to
		// the folder itself; what it gives a child shows in the list of that
		// child, which is checked when the child is
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%s has an access entry of type %d, which is not expected", dir, ace.Header.AceType)
		}
		if uint32(ace.Mask)&mask == 0 {
			continue
		}
		// #nosec G103 -- the SID starts at SidStart inside the ACE, per the ACCESS_ALLOWED_ACE layout
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if slices.Contains(trusted, sid) || isAppContainerSID(sid) {
			continue
		}
		return fmt.Errorf("%s can be changed by %s", dir, sid)
	}
	return nil
}

// isAppContainerSID reports whether sid is an app package or capability SID
// (S-1-15-2-..., S-1-15-3-...). Windows grants an app container a right only
// if the SIDs of its user are granted it as well, so such an entry never
// lets anyone do more than the other entries allow. User profile folders
// carry them (AppData grants one full control).
func isAppContainerSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-15-2-") || strings.HasPrefix(sid, "S-1-15-3-")
}

func checkDescriptor(sd *windows.SECURITY_DESCRIPTOR, path string, owners, allowed []string) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s has no owner", path)
	}
	if !slices.Contains(owners, owner.String()) {
		return fmt.Errorf("%s is owned by %s, which may change its permissions", path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no access list, so everyone may write to it", path)
	}
	for i := range uint32(dacl.AceCount) {
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
	return EnableTokenPrivileges(tok, names...)
}

// EnableTokenPrivileges turns on privileges tok already holds. tok needs
// TOKEN_ADJUST_PRIVILEGES.
func EnableTokenPrivileges(tok windows.Token, names ...string) error {
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
		// AdjustTokenPrivileges succeeds for a privilege the token does not
		// hold and reports it only through the last error, which x/sys
		// drops (review finding SE-01), so the call is made directly
		r, _, e := procAdjustTokenPrivileges.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0) // #nosec G103 -- the documented TOKEN_PRIVILEGES argument
		if r == 0 {
			return fmt.Errorf("enabling %s: %w", n, e)
		}
		if errors.Is(e, windows.ERROR_NOT_ALL_ASSIGNED) {
			return fmt.Errorf("enabling %s: the token does not hold it", n)
		}
	}
	return nil
}

// ForceSDDL applies an SDDL descriptor (owner if given, and a protected DACL)
// to an existing file or folder, and to nothing below it, through a
// backup-semantics handle, so that SeRestorePrivilege overrides whatever the
// current descriptor says. This is
// how the elevated setup role repairs folders whose descriptors lock even
// their owner out. The caller must have enabled SeRestorePrivilege.
//
// The descriptor must have a protected, non-NULL DACL (sdparse.Parse).
func ForceSDDL(path, sddl string) error {
	d, err := sdparse.Parse(sddl)
	if err != nil {
		return fmt.Errorf("permissions for %s: %w", path, err)
	}
	h, err := openForDescriptor(path, d)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // nothing to do on failure
	return applyDescriptor(h, d)
}

// openForDescriptor opens path, without following a reparse point and with
// backup semantics, for exactly the rights applyDescriptor needs.
func openForDescriptor(path string, d sdparse.Descriptor) (windows.Handle, error) {
	access := uint32(windows.WRITE_DAC)
	if d.Owner != nil {
		access |= windows.WRITE_OWNER
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("opening %s to set permissions: %w", path, err)
	}
	return h, nil
}

// applyDescriptor writes the owner of d (if it names one) and its DACL to
// the object h holds.
func applyDescriptor(h windows.Handle, d sdparse.Descriptor) error {
	// protection comes from the descriptor's own "D:P" control flag
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if d.Owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	// SetKernelObjectSecurity changes this object only. SetSecurityInfo would
	// also re-apply inheritance to everything below it, opening each child
	// without the restore privilege, and fail at the first child that
	// admits no administrators (the secrets folder).
	return windows.SetKernelObjectSecurity(h, info, d.SD)
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

// GrantSiteAccess gives the web worker and the supervisor their entries on a
// site folder (review finding SE-07). It opens path once, without following
// a link or junction, and refuses the folder if the handle is one; check
// (sitecheck.CheckRoot) then runs on the handle's real path, and the folder
// it approves must be the very folder the handle holds (same volume and file
// id). The permissions are read and written through that one handle, so a
// link swapped in after the check is never followed, and each entry is added
// only if no equivalent one is there, so repeated calls add nothing. The
// caller must be allowed to change the folder's permissions (normally its
// owner). It returns the canonical path check approved.
//
// The two accounts have types of their own (SE-06), so they cannot be swapped.
func GrantSiteAccess(path string, web WebSID, supervisor SupervisorSID, check func(string) (string, error)) (string, error) {
	h, info, err := openFolderNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only use after the write
	resolved, err := handlePath(h)
	if err != nil {
		return "", err
	}
	canon, err := check(resolved)
	if err != nil {
		return "", err
	}
	h2, info2, err := openFolderNoFollow(canon, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return "", err
	}
	_ = windows.CloseHandle(h2)
	if info.VolumeSerialNumber != info2.VolumeSerialNumber || info.FileIndexHigh != info2.FileIndexHigh || info.FileIndexLow != info2.FileIndexLow {
		return "", fmt.Errorf("%s changed while it was being checked; try again", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("reading permissions of %s: %w", canon, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	var add string
	if !hasAllow(dacl, string(web), siteWorkerMask, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) {
		add += "(A;OICI;" + siteWorkerAccess + ";;;" + string(web) + ")"
	}
	if !hasAllow(dacl, string(supervisor), siteSupervisorMask, 0) {
		add += "(A;;" + siteSupervisorAccess + ";;;" + string(supervisor) + ")"
	}
	if add == "" {
		return canon, nil
	}
	nsd, err := windows.SecurityDescriptorFromString(sd.String() + add)
	if err != nil {
		return "", err
	}
	ndacl, _, err := nsd.DACL()
	if err != nil {
		return "", err
	}
	// Through the handle: Windows applies the new inheritable entry to what
	// is inside the folder, and does not follow links or junctions inside it
	// (TestGrantSiteAccessStaysInside).
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, ndacl, nil); err != nil {
		return "", fmt.Errorf("setting permissions of %s: %w", canon, err)
	}
	return canon, nil
}

// Masks of the two site entries, as numbers.
const (
	siteWorkerMask     = 0x1200a9
	siteSupervisorMask = 0x120080
)

// hasAllow reports whether dacl holds an explicit allow entry for sid that
// grants at least mask with at least the given inheritance flags.
func hasAllow(dacl *windows.ACL, sid string, mask uint32, flags uint8) bool {
	if dacl == nil {
		return false
	}
	want, err := windows.StringToSid(sid)
	if err != nil {
		return false
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		if uint32(ace.Mask)&mask != mask || ace.Header.AceFlags&flags != flags {
			continue
		}
		got := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- the SID follows the ACE header, as the Windows ACE layout defines
		if got.Equals(want) {
			return true
		}
	}
	return false
}

// openFolderNoFollow opens a folder without following a link or junction
// and refuses it if it is one.
func openFolderNoFollow(path string, access uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, info, errors.New("not a valid path")
	}
	h, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, info, fmt.Errorf("cannot open %s: %w", path, err)
	}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, info, fmt.Errorf("cannot read %s: %w", path, err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, info, fmt.Errorf("%s is a link or junction; choose the folder it points to instead", path)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, info, fmt.Errorf("%s is not a folder", path)
	}
	return h, info, nil
}

// handlePath is the real path of an open file, in drive-letter form.
func handlePath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], windows.MAX_LONG_PATH, 0)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the folder: %w", err)
	}
	if int(n) >= len(buf) {
		return "", errors.New("the folder path is too long")
	}
	p := windows.UTF16ToString(buf[:n])
	if strings.HasPrefix(p, `\\?\UNC\`) {
		return "", errors.New("network folders cannot be published")
	}
	return strings.TrimPrefix(p, `\\?\`), nil
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
	for i := range uint32(dacl.AceCount) {
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
// than the caller needs SeRestorePrivilege enabled. The descriptor must have
// a protected, non-NULL DACL (sdparse.Parse).
func CreateFolderSDDL(path, sddl string) error {
	d, err := sdparse.Parse(sddl)
	if err != nil {
		return fmt.Errorf("permissions for %s: %w", path, err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: d.SD}
	sa.Length = uint32(unsafe.Sizeof(sa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	return windows.CreateDirectory(p, &sa)
}

// ErrHardLinked is returned by ForceSDDLUnlessLinked for a file it left
// alone because it has more than one hard link.
var ErrHardLinked = errors.New("has more than one hard link, so its permissions were left alone")

// ForceSDDLUnlessLinked is ForceSDDL, except that a file with more than one
// hard link is left alone and ErrHardLinked returned: re-permissioning it
// would also change the file at the other end of the link, which may be
// anywhere on the volume. The link count is read and the descriptor written
// through one handle, so the file checked is the file changed (review
// finding SE-08). The count is read again afterwards, and a link added in
// between is reported as an error; the descriptor has then been written
// already, so that error says only that another file may share it now.
func ForceSDDLUnlessLinked(path, sddl string) error {
	d, err := sdparse.Parse(sddl)
	if err != nil {
		return fmt.Errorf("permissions for %s: %w", path, err)
	}
	h, err := openForDescriptor(path, d)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // nothing to do on failure
	linked := func() (bool, error) {
		fi, err := standardInfo(h)
		if err != nil {
			return false, fmt.Errorf("reading %s: %w", path, err)
		}
		return fi.Directory == 0 && fi.NumberOfLinks > 1, nil
	}
	if l, err := linked(); err != nil {
		return err
	} else if l {
		return fmt.Errorf("%s %w", path, ErrHardLinked)
	}
	if err := applyDescriptor(h, d); err != nil {
		return err
	}
	if l, err := linked(); err != nil {
		return err
	} else if l {
		return fmt.Errorf("%s gained a hard link while its permissions were set", path)
	}
	return nil
}

// CreateMutexSDDL creates or opens a named mutex with the given descriptor.
// existed reports that the mutex was already there, in which case its own
// descriptor applies and the caller should check its owner (OwnerOf).
func CreateMutexSDDL(name, sddl string) (h windows.Handle, existed bool, err error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, false, fmt.Errorf("security descriptor: %w", err)
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa)) // #nosec G103 G115 -- the size of a fixed Windows structure
	h, err = windows.CreateMutex(&sa, false, p)
	if h == 0 {
		return 0, false, err
	}
	return h, errors.Is(err, windows.ERROR_ALREADY_EXISTS), nil
}

// OwnerOf returns the owner SID of a kernel object, as a string.
func OwnerOf(h windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	o, _, err := sd.Owner()
	if err != nil || o == nil {
		return "", errors.New("no owner")
	}
	return o.String(), nil
}
