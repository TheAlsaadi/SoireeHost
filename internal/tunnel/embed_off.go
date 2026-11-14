//go:build !cloudflared

package tunnel

// embedded is empty in builds without the cloudflared tag: tests, linters and
// local development builds need neither the 55 MB file nor a download.
// Release builds always use the tag (ADR-0007).
var embedded []byte
