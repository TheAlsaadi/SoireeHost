//go:build production

package setup

// requireCloudflared: a release build must carry cloudflared; setup refuses
// to install one that does not (ADR-0007).
const requireCloudflared = true
