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
	// SIDCreatorOwner is the inherit-only placeholder in Program Files' list.
	SIDCreatorOwner = "S-1-3-0"
	// SIDTrustedInstaller owns Windows' own files and Program Files.
	SIDTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
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
	for i := range 5 {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return sb.String()
}

// Role SIDs (review finding SE-06). The SID of each SoiréeHost service
// account has a type of its own, so passing one role's SID where another
// role's is expected does not compile: a swapped call would otherwise, for
// example, grant the supervisor read access to every site file. Convert a
// plain string to one of these only where the SID is known to be that
// role's (tests run every role as the test account).

// SupervisorSID is the SID of the supervisor's account.
type SupervisorSID string

// WebSID is the SID of the web worker's account.
type WebSID string

// TunnelSID is the SID of the tunnel launcher's account.
type TunnelSID string

// WorkerSID is the SID of either worker's account.
type WorkerSID interface{ WebSID | TunnelSID }

// SupervisorAccount is the SID of NT SERVICE\SoireeHost.
func SupervisorAccount() SupervisorSID { return SupervisorSID(ServiceSID(SupervisorService)) }

// WebAccount is the SID of NT SERVICE\SoireeHostWeb.
func WebAccount() WebSID { return WebSID(ServiceSID(WebService)) }

// TunnelAccount is the SID of NT SERVICE\SoireeHostTunnel.
func TunnelAccount() TunnelSID { return TunnelSID(ServiceSID(TunnelService)) }
