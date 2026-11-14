package winsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RestrictDLLSearch makes every later DLL load in this process search
// System32 only (S-24). Each role calls it first thing.
func RestrictDLLSearch() error {
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		return fmt.Errorf("restricting DLL search to System32: %w", err)
	}
	return nil
}

// Limits are the self-imposed limits of a worker (S-21).
type Limits struct {
	// MemoryBytes caps the committed memory of each process in the job.
	MemoryBytes uint64
	// ActiveProcesses caps the processes in the job: 1 means this process
	// can start no other; the tunnel launcher uses 2 for cloudflared.
	ActiveProcesses uint32
	// NoChildProcesses turns on the mitigation policy that makes process
	// creation fail outright for this process.
	NoChildProcesses bool
}

// Confine applies every limit to the current process: drops all privileges
// but SeChangeNotifyPrivilege, joins a kill-on-close job object with the
// process, memory and UI limits, and, if asked, forbids child processes. The
// job handle is deliberately never closed: closing it would end the process.
// Any failure is returned; the caller must exit rather than run unconfined.
func Confine(l Limits) error {
	if l.ActiveProcesses == 0 || l.MemoryBytes == 0 {
		return errors.New("confine: limits must be set")
	}
	if err := DropPrivileges("SeChangeNotifyPrivilege"); err != nil {
		return err
	}
	if err := joinJob(l); err != nil {
		return err
	}
	if l.NoChildProcesses {
		if err := disallowChildProcesses(); err != nil {
			return err
		}
	}
	return nil
}

// DropPrivileges removes from the process token every privilege not named in
// keep. Removed privileges cannot be re-enabled.
func DropPrivileges(keep ...string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &tok); err != nil {
		return fmt.Errorf("opening process token: %w", err)
	}
	defer tok.Close() //nolint:errcheck // nothing to do on failure
	keepLUIDs := map[windows.LUID]bool{}
	for _, name := range keep {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			return fmt.Errorf("looking up %s: %w", name, err)
		}
		keepLUIDs[luid] = true
	}
	privs, err := tokenPrivileges(tok)
	if err != nil {
		return err
	}
	for _, luid := range privs {
		if keepLUIDs[luid] {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_REMOVED}
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			return fmt.Errorf("removing a privilege: %w", err)
		}
	}
	return nil
}

// Privileges lists the privilege LUIDs left in the current process token.
func Privileges() ([]windows.LUID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return nil, err
	}
	defer tok.Close() //nolint:errcheck // nothing to do on failure
	return tokenPrivileges(tok)
}

// tokenPrivileges reads TOKEN_PRIVILEGES: a DWORD count, then count entries
// of a LUID (8 bytes) and attributes (4 bytes).
func tokenPrivileges(tok windows.Token) ([]windows.LUID, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	if n < 4 {
		return nil, errors.New("reading token privileges: empty result")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n); err != nil {
		return nil, fmt.Errorf("reading token privileges: %w", err)
	}
	count := int(binary.LittleEndian.Uint32(buf))
	if count < 0 || 4+12*count > len(buf) {
		return nil, errors.New("reading token privileges: malformed result")
	}
	out := make([]windows.LUID, count)
	for i := range count {
		e := buf[4+12*i:]
		out[i] = windows.LUID{LowPart: binary.LittleEndian.Uint32(e), HighPart: int32(binary.LittleEndian.Uint32(e[4:]))} // #nosec G115 -- HighPart is a signed DWORD by definition
	}
	return out, nil
}

func joinJob(l Limits) error {
	job, err := newJob(l)
	if err != nil {
		return err
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		return fmt.Errorf("joining job object: %w", err)
	}
	return nil
}

// newJob creates a kill-on-close job object with the process, memory and UI
// limits of l. The caller owns the handle; closing it ends every process in
// the job.
func newJob(l Limits) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("creating job object: %w", err)
	}
	if err := limitJob(job, l); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func limitJob(job windows.Handle, l Limits) error {
	ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
		windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	ext.BasicLimitInformation.ActiveProcessLimit = l.ActiveProcesses
	ext.ProcessMemoryLimit = uintptr(l.MemoryBytes)
	// #nosec G103 -- passing a struct and its size to a Windows API, as its documentation requires
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		return fmt.Errorf("setting job limits: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	// #nosec G103 -- as above
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return fmt.Errorf("setting job UI limits: %w", err)
	}
	return nil
}

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessMitigationPolicy = kernel32.NewProc("SetProcessMitigationPolicy")
)

// processChildProcessPolicy is PROCESS_MITIGATION_POLICY value 13.
const processChildProcessPolicy = 13

func disallowChildProcesses() error {
	// PROCESS_MITIGATION_CHILD_PROCESS_POLICY: bit 0 is NoChildProcessCreation
	flags := uint32(1)
	// #nosec G103 -- passing a DWORD and its size to a Windows API, as its documentation requires
	r, _, err := procSetProcessMitigationPolicy.Call(processChildProcessPolicy, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	if r == 0 {
		return fmt.Errorf("forbidding child processes: %w", err)
	}
	return nil
}
