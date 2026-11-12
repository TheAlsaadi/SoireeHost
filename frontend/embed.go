// Package frontend embeds the built control-panel UI (frontend/dist) into
// soireehost.exe. Run the frontend build before building the Go binary;
// without it the window opens empty.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Assets returns the built UI rooted at dist/.
func Assets() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
