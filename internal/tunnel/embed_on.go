//go:build cloudflared

package tunnel

import _ "embed" // for go:embed

// embedded is the official cloudflared-windows-amd64.exe, which
// build/fetch-cloudflared.ps1 downloads and checks against
// build/cloudflared.lock before the build (S-71).
//
//go:embed embed/cloudflared.exe
var embedded []byte
