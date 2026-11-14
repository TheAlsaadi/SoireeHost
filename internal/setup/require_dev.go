//go:build !production

package setup

// requireCloudflared: a development build may install without cloudflared;
// the tunnel then reports Repair needed.
const requireCloudflared = false
