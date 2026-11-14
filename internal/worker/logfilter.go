package worker

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(HeaderFilter{})
	caddy.RegisterModule(QueryFilter{})
}

// Redacted replaces every value the logs must not keep.
const Redacted = "REDACTED"

// loggedHeaders is the allow-list of request and response headers written to
// the logs (S-18). Everything else, including Authorization, Cookie,
// Set-Cookie, Cf-Access-Jwt-Assertion and any custom API-key header, is left
// out. An allow-list fails closed: a new credential header is never logged by
// accident.
var loggedHeaders = map[string]bool{
	"Accept":           true,
	"Accept-Encoding":  true,
	"Accept-Language":  true,
	"Cf-Connecting-Ip": true,
	"Cf-Ipcountry":     true,
	"Cf-Ray":           true,
	"Content-Length":   true,
	"Content-Type":     true,
	"Referer":          true,
	"User-Agent":       true,
}

// HeaderFilter is a Caddy log field filter that keeps only allow-listed
// headers, and masks every query value inside Referer.
type HeaderFilter struct{}

// CaddyModule returns the Caddy module information.
func (HeaderFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.soireehost_headers",
		New: func() caddy.Module { return new(HeaderFilter) },
	}
}

// Filter implements logging.LogFieldFilter. A field of any unexpected type is
// dropped.
func (HeaderFilter) Filter(in zapcore.Field) zapcore.Field {
	lh, ok := in.Interface.(caddyhttp.LoggableHTTPHeader)
	if !ok {
		in.Type = zapcore.SkipType
		return in
	}
	return zap.Object(in.Key, caddyhttp.LoggableHTTPHeader{Header: FilterHeaders(lh.Header)})
}

// FilterHeaders returns a copy of h with only the allow-listed headers, and
// with every query value in Referer masked.
func FilterHeaders(h http.Header) http.Header {
	out := make(http.Header, len(loggedHeaders))
	for k, v := range h {
		ck := http.CanonicalHeaderKey(k)
		if !loggedHeaders[ck] {
			continue
		}
		vals := make([]string, len(v))
		for i, s := range v {
			if ck == "Referer" {
				s = RedactURI(s)
			}
			vals[i] = s
		}
		out[ck] = vals
	}
	return out
}

// QueryFilter is a Caddy log field filter for URI strings: it masks every
// query value.
type QueryFilter struct{}

// CaddyModule returns the Caddy module information.
func (QueryFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.soireehost_query",
		New: func() caddy.Module { return new(QueryFilter) },
	}
}

// Filter implements logging.LogFieldFilter. A non-string field is dropped.
func (QueryFilter) Filter(in zapcore.Field) zapcore.Field {
	if in.Type != zapcore.StringType {
		in.Type = zapcore.SkipType
		return in
	}
	in.String = RedactURI(in.String)
	return in
}

// RedactURI masks every query value in a request URI or URL (S-18) and keeps
// the parameter names, their order and the path. Masking every value fails
// closed: credentials travel under many names (code, sig, jwt, otp, ticket,
// SAMLResponse, ...), and a list of secret-looking names always misses some.
// Everything after the first '?' is treated as query, including a raw '#':
// Go's server does not split a fragment off the request target, so a value
// after '#' reaches the app as a parameter and must be masked too. If a name
// cannot be decoded, the whole query is masked.
func RedactURI(uri string) string {
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
				return base + "?" + Redacted
			}
			if hasValue {
				parts[i] = name + "=" + Redacted
			} else {
				// a bare item (/verify?eyJhbGci...) may itself be the token
				parts[i] = Redacted
			}
		}
		groups[gi] = strings.Join(parts, ";")
	}
	return base + "?" + strings.Join(groups, "&")
}
