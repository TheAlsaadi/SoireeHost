// Package sitecheck holds the rules that decide which request paths a site may
// serve (S-12, S-13) and which folders may be published (S-11).
package sitecheck

import (
	"path"
	"strings"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// Verdict is the outcome of a request path check.
type Verdict int

const (
	// Allow lets the request through.
	Allow Verdict = iota
	// BadRequest means the path is malformed or uses a Windows path trick;
	// answer 400.
	BadRequest
	// NotFound means the path names something that is never served (a
	// dotfile, a key, a backup); answer 404 so its existence is not revealed.
	NotFound
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case BadRequest:
		return "bad request"
	case NotFound:
		return "not found"
	}
	return "unknown"
}

// MaxPathLen bounds the length of a request path.
const MaxPathLen = 2048

// Names that are never served, compared case-insensitively (S-12).
var blockedNames = map[string]bool{
	"web.config":  true,
	"desktop.ini": true,
	"thumbs.db":   true,
	// a user profile's application data (browser passwords and cookies,
	// mail, tokens) and its registry hive, wherever the profile lives (S-11)
	"appdata":    true,
	"ntuser.dat": true,
	// SSH private keys carry no extension
	"id_rsa":        true,
	"id_dsa":        true,
	"id_ecdsa":      true,
	"id_ed25519":    true,
	"id_ecdsa_sk":   true,
	"id_ed25519_sk": true,
}

// Extensions that are never served, compared case-insensitively (S-12).
// .p12 is the same format as .pfx.
var blockedExts = map[string]bool{
	".pem": true,
	".key": true,
	".pfx": true,
	".p12": true,
	".bak": true,
	".sql": true,
	// PuTTY private keys and KeePass password databases
	".ppk":  true,
	".kdbx": true,
}

// WellKnown is the one dot-folder a site may opt in to serving (RFC 8615):
// security.txt, OpenID discovery and app-site association files live there.
const WellKnown = ".well-known"

// Rules are the per-site choices that change the path rules.
type Rules struct {
	// AllowWellKnown lets requests into /.well-known/. Only that exact,
	// lower-case first path segment is exempt from the dotfile rule; every
	// other rule still applies to everything inside it.
	AllowWellKnown bool
}

// exempt reports whether segment number i of a path is the opted-in
// /.well-known/ folder.
func (ru Rules) exempt(i int, seg string) bool {
	return ru.AllowWellKnown && i == 0 && seg == WellKnown
}

// CheckStatic applies the default rules for a static site.
func CheckStatic(decoded, raw string) Verdict { return Rules{}.Static(decoded, raw) }

// CheckProxy applies the default rules for a proxied app.
func CheckProxy(decoded, raw string) Verdict { return Rules{}.Proxy(decoded, raw) }

// Static applies every rule for a static site. decoded is the
// percent-decoded request path (r.URL.Path); raw is the path as sent on the
// wire, before decoding (the part of the request target before '?').
func (ru Rules) Static(decoded, raw string) Verdict {
	if v := checkCommon(decoded, raw); v != Allow {
		return v
	}
	if strings.HasPrefix(decoded, "//") {
		// would make a protocol-relative redirect target
		return BadRequest
	}
	if strings.Contains(raw, "%25") {
		// a literal '%' after decoding means the client double-encoded
		return BadRequest
	}
	for _, r := range decoded {
		if strings.ContainsRune(`:*?"<>|`, r) {
			// ':' covers alternate data streams (file::$DATA) and drive letters
			return BadRequest
		}
	}
	verdict := Allow
	for i, seg := range strings.Split(decoded[1:], "/") {
		if seg == "" {
			continue
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return BadRequest
		}
		if config.IsReservedDeviceName(seg) || config.HasShortNameMarker(seg) {
			return BadRequest
		}
		if hiddenOrBlocked(seg) && !ru.exempt(i, seg) {
			verdict = NotFound
		}
	}
	return verdict
}

// Proxy applies the rules for a proxied app. The app owns its own URL
// space, so Windows file name rules do not make a request malformed there
// (/api/user:123 must work), but traversal, control characters, backslashes
// and the never-serve list still apply. Many apps on Windows hand the path to
// the file system, which strips trailing dots and spaces, resolves ::$DATA and
// expands 8.3 short names, so the never-serve check looks at each segment the
// way Windows would open it.
func (ru Rules) Proxy(decoded, raw string) Verdict {
	if v := checkCommon(decoded, raw); v != Allow {
		return v
	}
	for i, seg := range strings.Split(decoded[1:], "/") {
		if seg == "" || ru.exempt(i, seg) {
			continue
		}
		if hiddenOrBlocked(seg) || hiddenOrBlocked(windowsName(seg)) || looksLikeShortName(seg) {
			return NotFound
		}
	}
	return Allow
}

// windowsName returns the file name Windows would open for a path segment:
// anything from the first ':' on (a stream name) is dropped, then trailing
// dots and spaces.
func windowsName(seg string) string {
	seg, _, _ = strings.Cut(seg, ":")
	return strings.TrimRight(seg, ". ")
}

// looksLikeShortName reports whether a segment has the shape of an 8.3 short
// name with a ~N tail (GIT~1, ENV~1, SERVER~1.KEY), which can alias a hidden
// or blocked file.
func looksLikeShortName(seg string) bool {
	name := windowsName(seg)
	base, ext, _ := strings.Cut(name, ".")
	if len(base) == 0 || len(base) > 8 || len(ext) > 3 || strings.Contains(ext, ".") {
		return false
	}
	return config.HasShortNameMarker(base)
}

// CheckName reports whether a single file name may be served from a static
// site; it is used to filter directory listings.
func CheckName(name string) bool {
	return CheckStatic("/"+name, "/"+name) == Allow
}

func checkCommon(decoded, raw string) Verdict {
	if decoded == "" || decoded[0] != '/' || len(decoded) > MaxPathLen || len(raw) > 3*MaxPathLen {
		return BadRequest
	}
	if !utf8.ValidString(decoded) {
		return BadRequest
	}
	lowRaw := strings.ToLower(raw)
	if strings.Contains(raw, `\`) || strings.Contains(lowRaw, "%5c") || strings.Contains(lowRaw, "%00") {
		return BadRequest
	}
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if c < 0x20 || c == 0x7f || c == '\\' {
			return BadRequest
		}
	}
	for seg := range strings.SplitSeq(decoded[1:], "/") {
		if seg == "." || seg == ".." {
			return BadRequest
		}
	}
	return Allow
}

func hiddenOrBlocked(seg string) bool {
	if strings.HasPrefix(seg, ".") {
		return true
	}
	lower := strings.ToLower(seg)
	if blockedNames[lower] {
		return true
	}
	// OpenSSH server host keys: ssh_host_<type>_key (the .pub halves are fine)
	if strings.HasPrefix(lower, "ssh_host_") && strings.HasSuffix(lower, "_key") {
		return true
	}
	return blockedExts[path.Ext(lower)]
}
