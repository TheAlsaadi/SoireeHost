package winsec

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

// Caller is who is on the other end of a pipe.
type Caller struct {
	// SID is the user SID of the client's token.
	SID string
	// Admin is true when the token carries the Administrators group enabled,
	// which under UAC means an elevated process.
	Admin bool
}

// PipeCaller identifies the client of a connected server-side pipe handle.
// It impersonates the client on a locked OS thread only long enough to read
// the thread token, then reverts. Clients connect at Identification level,
// so the token can be read but not used to act as the client. If reverting
// fails the process must not continue, so PipeCaller panics.
func PipeCaller(h windows.Handle) (Caller, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if r, _, err := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		return Caller{}, fmt.Errorf("identifying pipe client: %w", err)
	}
	var tok windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err := windows.RevertToSelf(); err != nil {
		panic("RevertToSelf failed after identifying a pipe client: " + err.Error())
	}
	if openErr != nil {
		return Caller{}, fmt.Errorf("reading pipe client token: %w", openErr)
	}
	defer tok.Close() //nolint:errcheck // nothing to do on failure
	return tokenCaller(tok)
}

// CurrentCaller describes the current process the way PipeCaller would.
func CurrentCaller() (Caller, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return Caller{}, err
	}
	defer tok.Close() //nolint:errcheck // nothing to do on failure
	return tokenCaller(tok)
}

func tokenCaller(tok windows.Token) (Caller, error) {
	u, err := tok.GetTokenUser()
	if err != nil {
		return Caller{}, fmt.Errorf("reading token user: %w", err)
	}
	c := Caller{SID: u.User.Sid.String()}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return Caller{}, fmt.Errorf("reading token groups: %w", err)
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.String() == SIDAdministrators && g.Attributes&windows.SE_GROUP_ENABLED != 0 &&
			g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			c.Admin = true
		}
	}
	return c, nil
}

// HandleOwner returns the owner SID of a kernel object, such as the client
// end of a pipe. The handle needs READ_CONTROL, which GENERIC_READ includes.
func HandleOwner(h windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("reading owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", errors.New("object has no owner")
	}
	return owner.String(), nil
}
