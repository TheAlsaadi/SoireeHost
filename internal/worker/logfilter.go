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

// secretParamWords: a query parameter whose lower-cased name contains one of
// these has its value masked (S-18).
var secretParamWords = []string{"token", "key", "password", "passwd", "pwd", "secret", "auth", "session", "signature", "credential"}

// HeaderFilter is a Caddy log field filter that keeps only allow-listed
// headers, and masks secret query parameters inside Referer.
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
// with secret query values in Referer masked.
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

// QueryFilter is a Caddy log field filter for URI strings: it masks the values
// of query parameters whose names look secret.
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

// RedactURI masks the values of secret-looking query parameters in a request
// URI or URL. If the query cannot be parsed, the whole query is masked.
// Parameter names, order and the rest of the URI are kept.
func RedactURI(uri string) string {
	base, query, hasQuery := strings.Cut(uri, "?")
	if !hasQuery {
		return uri
	}
	query, frag, hasFrag := strings.Cut(query, "#")
	// ';' is not a separator for Go, but some apps treat it as one, so a
	// value after it is masked as if it were its own parameter
	groups := strings.Split(query, "&")
	for gi, g := range groups {
		parts := strings.Split(g, ";")
		for i, p := range parts {
			if p == "" {
				continue
			}
			name, _, hasValue := strings.Cut(p, "=")
			decoded, err := url.QueryUnescape(name)
			if err != nil {
				// a name we cannot read may hide anything
				return base + "?" + Redacted
			}
			if hasValue && isSecretParam(decoded) {
				parts[i] = name + "=" + Redacted
			}
		}
		groups[gi] = strings.Join(parts, ";")
	}
	out := base + "?" + strings.Join(groups, "&")
	if hasFrag {
		out += "#" + frag
	}
	return out
}

func isSecretParam(name string) bool {
	n := strings.ToLower(name)
	for _, w := range secretParamWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}
