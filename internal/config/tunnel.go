package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// ErrNotTunnelToken is the one answer for anything that is not a Cloudflare
// Tunnel token. It never repeats the value (S-40), and it says why an API key
// or API token is refused (S-50).
var ErrNotTunnelToken = errors.New("this is not a Cloudflare Tunnel token. Copy the token from the tunnel's install command in the Cloudflare dashboard. An API key or API token cannot be used")

// MaxTunnelTokenLen bounds a tunnel token. Real ones are about 180 to 250
// characters.
const MaxTunnelTokenLen = 1024

var (
	accountTagRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRe       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	endpointRe   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	// QuickShareHostRe is a trycloudflare.com quick tunnel hostname: one
	// label under trycloudflare.com and nothing else (ADR-0007).
	quickShareHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$`)
)

// tunnelToken is cloudflared's token: standard base64 of this JSON object
// (cloudflared connection.TunnelToken, checked at 2026.11.0).
type tunnelToken struct {
	AccountTag string `json:"a"`
	Secret     string `json:"s"`
	TunnelID   string `json:"t"`
	Endpoint   string `json:"e,omitempty"`
}

// TunnelTokenParts are the token's secret pieces, which a log scrubber must
// hide besides the token itself (R-21).
type TunnelTokenParts struct {
	AccountTag string
	Secret     string // as in the token: base64
}

// ValidateTunnelToken accepts only a Cloudflare Tunnel token, which can run
// exactly one tunnel (S-50): standard base64 of a JSON object with exactly
// the keys a (32 hex digits), t (a UUID), s (base64 of 32 to 256 bytes) and
// optionally e (a short lower-case label). A Global API Key (37 hex digits),
// an API token (40 characters of base64url), a certificate, or any other
// text is refused.
func ValidateTunnelToken(tok string) (TunnelTokenParts, error) {
	if tok == "" || len(tok) > MaxTunnelTokenLen || strings.TrimSpace(tok) != tok {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(tok)
	if err != nil {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t tunnelToken
	if err := dec.Decode(&t); err != nil {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	// encoding/json matches keys case-insensitively; a token Cloudflare
	// issues spells them exactly a, s, t and e, so anything else is refused
	// (found by FuzzTunnelToken)
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	for k := range keys {
		if k != "a" && k != "s" && k != "t" && k != "e" {
			return TunnelTokenParts{}, ErrNotTunnelToken
		}
	}
	if !accountTagRe.MatchString(t.AccountTag) || !uuidRe.MatchString(t.TunnelID) {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	if t.Endpoint != "" && !endpointRe.MatchString(t.Endpoint) {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	sec, err := base64.StdEncoding.Strict().DecodeString(t.Secret)
	if err != nil || len(sec) < 32 || len(sec) > 256 {
		return TunnelTokenParts{}, ErrNotTunnelToken
	}
	return TunnelTokenParts{AccountTag: t.AccountTag, Secret: t.Secret}, nil
}

// ValidQuickShareHostname reports whether h is a hostname cloudflared can
// have been given for a quick share: exactly one label under
// trycloudflare.com that is also a valid hostname here.
func ValidQuickShareHostname(h string) bool {
	return quickShareHostRe.MatchString(h) && ValidateHostname(h) == nil
}
