// Package winsec holds the Windows security building blocks SoiréeHost uses:
// service SIDs, security descriptors for pipes, folders and services, the
// folder ACL check (S-22), process self-confinement (S-21, S-24) and pipe
// identity checks (S-30). See docs/adr/0006-supervisor-ipc-and-stores.md.
package winsec

import (
	"crypto/sha1" // #nosec G505 -- Windows defines service SIDs with SHA-1; it is not used as a security hash here
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Service names. Every SoiréeHost service runs under the virtual account
// NT SERVICE\<name>, whose SID is derived from the name.
const (
	SupervisorService = "SoireeHost"
	WebService        = "SoireeHostWeb"
	TunnelService     = "SoireeHostTunnel"
)

// Well-known SIDs in string form.
const (
	SIDSystem         = "S-1-5-18"
	SIDAdministrators = "S-1-5-32-544"
	SIDNetwork        = "S-1-5-2"
	SIDInteractive    = "S-1-5-4"
	SIDOwnerRights    = "S-1-3-4"
	SIDUsers          = "S-1-5-32-545"
	SIDAuthenticated  = "S-1-5-11"
	SIDEveryone       = "S-1-1-0"
)

// ServiceSID returns the SID of the virtual account NT SERVICE\<name>, as
// Windows computes it: S-1-5-80 followed by the SHA-1 of the upper-case
// service name in UTF-16LE, read as five little-endian 32-bit values. It does
// not need the service to exist.
func ServiceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], u)
	}
	sum := sha1.Sum(buf) // #nosec G401 -- see the import comment
	var sb strings.Builder
	sb.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return sb.String()
}
