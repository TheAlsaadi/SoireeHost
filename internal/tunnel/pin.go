// Package tunnel is the tunnel launcher (ADR-0007): it runs the embedded,
// hash-checked cloudflared for the tunnel token and for each quick share,
// confined, and reports their health to the supervisor without ever passing
// cloudflared's own text along.
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// The cloudflared release compiled into this build (S-23, S-71). The values
// must equal build/cloudflared.lock; TestPinMatchesLock checks that.
const (
	CloudflaredVersion = "2026.11.1"
	CloudflaredSHA256  = "341deda3db5ec498a0482254d6c38c0b7cf01a30c37bb5dd95d2216d08955e35"
)

// ExeName is cloudflared's file name in the install folder.
const ExeName = "cloudflared.exe"

// ErrNotEmbedded means this build carries no cloudflared (built without the
// cloudflared tag): the tunnel then reports Repair needed.
var ErrNotEmbedded = errors.New("this build of SoiréeHost does not contain cloudflared")

// Embedded returns the cloudflared bytes compiled into this build, after
// checking them against the pin. Setup writes them to the install folder.
func Embedded() ([]byte, error) {
	if len(embedded) == 0 {
		return nil, ErrNotEmbedded
	}
	sum := sha256.Sum256(embedded)
	if hex.EncodeToString(sum[:]) != CloudflaredSHA256 {
		return nil, errors.New("the cloudflared inside this build does not match its pinned hash")
	}
	return embedded, nil
}
