package winsec

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// UserSID checks that s is exactly one user account's SID, in canonical
// form, and returns it. It accepts local and domain accounts (S-1-5-21-...)
// and Microsoft Entra accounts (S-1-12-1-...), and refuses well-known
// groups, service and system SIDs, and any text that is not a single SID.
// The descriptor builders paste SIDs into SDDL, so a SID read from a file
// passes through here first (review finding SE-05).
func UserSID(s string) (string, error) {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a SID", s)
	}
	c := sid.String()
	if c != s {
		return "", fmt.Errorf("%q is not a SID in canonical form", s)
	}
	if !strings.HasPrefix(c, "S-1-5-21-") && !strings.HasPrefix(c, "S-1-12-1-") {
		return "", fmt.Errorf("%s is not a user account", c)
	}
	return c, nil
}
