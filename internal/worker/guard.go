package worker

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

func init() {
	caddy.RegisterModule(Guard{})
}

// Guard is the first SoiréeHost handler in every site route. It drops
// forwarded-for headers the client may have forged (S-05) and refuses request
// paths that break the S-12 and S-13 rules before any file is touched.
type Guard struct {
	// Mode is "static" or "proxy" and selects the path rules.
	Mode string `json:"mode"`
	// AllowWellKnown is the site's opt-in to serving /.well-known/.
	AllowWellKnown bool `json:"allow_well_known,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.soireehost_guard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// Provision checks the mode.
func (g *Guard) Provision(caddy.Context) error {
	if g.Mode != "static" && g.Mode != "proxy" {
		return fmt.Errorf("soireehost_guard: unknown mode %q", g.Mode)
	}
	return nil
}

// forwardedHeaders are headers a client can use to claim another address or
// host. cloudflared on loopback is the only real client, and the address it
// vouches for arrives in CF-Connecting-IP, so all of these are dropped.
var forwardedHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Server",
	"X-Original-Forwarded-For",
	"X-Real-Ip",
	"X-Client-Ip",
	"X-Cluster-Client-Ip",
	"X-Originating-Ip",
	"X-Remote-Ip",
	"X-Remote-Addr",
	"X-Proxyuser-Ip",
	"Client-Ip",
	"True-Client-Ip",
	"Fastly-Client-Ip",
	"Forwarded",
}

// StripForwarded removes forged forwarding headers from h. X-Forwarded-Proto
// is kept only when it is exactly "http" or "https", because Cloudflare's edge
// sets it and apps need it to build correct links.
func StripForwarded(h http.Header) {
	for _, k := range forwardedHeaders {
		delete(h, k)
	}
	// Spellings with '_' instead of '-' (X_Forwarded_For) reach apps that read
	// headers through CGI-style variables, where both become HTTP_X_FORWARDED_FOR.
	for k := range h {
		if !strings.Contains(k, "_") {
			continue
		}
		alias := http.CanonicalHeaderKey(strings.ReplaceAll(k, "_", "-"))
		if alias == "X-Forwarded-Proto" || slices.Contains(forwardedHeaders, alias) {
			delete(h, k)
		}
	}
	if v := h.Values("X-Forwarded-Proto"); len(v) != 1 || (v[0] != "https" && v[0] != "http") {
		delete(h, "X-Forwarded-Proto")
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (g Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	StripForwarded(r.Header)

	raw := r.RequestURI
	if strings.HasPrefix(raw, "/") {
		raw, _, _ = strings.Cut(raw, "?")
	} else {
		// absolute-form or asterisk-form request target
		raw = r.URL.EscapedPath()
	}
	rules := sitecheck.Rules{AllowWellKnown: g.AllowWellKnown}
	var v sitecheck.Verdict
	if g.Mode == "static" {
		v = rules.Static(r.URL.Path, raw)
	} else {
		v = rules.Proxy(r.URL.Path, raw)
	}
	switch v {
	case sitecheck.Allow:
		return next.ServeHTTP(w, r)
	case sitecheck.NotFound:
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("path refused: %s", v))
	default:
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("path refused: %s", v))
	}
}

var (
	_ caddy.Provisioner           = (*Guard)(nil)
	_ caddyhttp.MiddlewareHandler = (*Guard)(nil)
)
