// Package redact masks request data before it is written to any log (S-18).
// It has no dependencies, so both the web worker's log filters and the
// firewall event log use the same rules.
package redact

import (
	"net/url"
	"strings"
)

// Masked replaces every value the logs must not keep.
const Masked = "REDACTED"

// URI masks every query value in a request URI or URL (S-18) and keeps the
// parameter names, their order and the path. Masking every value fails
// closed: credentials travel under many names (code, sig, jwt, otp, ticket,
// SAMLResponse, ...), and a list of secret-looking names always misses some.
// Everything after the first '?' is treated as query, including a raw '#':
// Go's server does not split a fragment off the request target, so a value
// after '#' reaches the app as a parameter and must be masked too. If a name
// cannot be decoded, the whole query is masked.
func URI(uri string) string {
	base, query, hasQuery := strings.Cut(uri, "?")
	if !hasQuery {
		return uri
	}
	// ';' is not a separator for Go, but some apps treat it as one, so each
	// ';' part is masked as if it were its own parameter
	groups := strings.Split(query, "&")
	for gi, g := range groups {
		parts := strings.Split(g, ";")
		for i, p := range parts {
			if p == "" {
				continue
			}
			name, _, hasValue := strings.Cut(p, "=")
			if _, err := url.QueryUnescape(name); err != nil {
				// a name we cannot read may hide anything
				return base + "?" + Masked
			}
			if hasValue {
				parts[i] = name + "=" + Masked
			} else {
				// a bare item (/verify?eyJhbGci...) may itself be the token
				parts[i] = Masked
			}
		}
		groups[gi] = strings.Join(parts, ";")
	}
	return base + "?" + strings.Join(groups, "&")
}
