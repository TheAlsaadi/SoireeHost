package worker

import (
	"fmt"
	"io"
	"net/http"
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

// isForwardingName reports whether a header name is one a client can use to
// claim another address or host (S-05). cloudflared on loopback is the only
// real client, and the address it vouches for arrives in CF-Connecting-IP, so
// every such header is dropped. The rule is by shape, not a fixed list,
// because apps and frameworks read many spellings (Forwarded-For,
// X-Forwarded-By, Proxy-Client-IP, WL-Proxy-Client-IP, ...). '_' counts as
// '-', since apps that read headers as CGI-style variables see both as the
// same name.
func isForwardingName(k string) bool {
	n := strings.ToLower(strings.ReplaceAll(k, "_", "-"))
	if strings.Contains(n, "forwarded") || strings.Contains(n, "clientip") || strings.Contains(n, "client-ip") ||
		strings.Contains(n, "socketip") || strings.Contains(n, "remote-addr") || strings.Contains(n, "external-address") {
		return true
	}
	for _, suf := range []string{"-ip", "-ipv4", "-ipv6"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

// StripForwarded removes forged forwarding headers from h. Two names survive
// in their exact canonical spelling: Cf-Connecting-Ip, which cloudflared sets
// and Caddy reads for the client address, and X-Forwarded-Proto when it is
// exactly "http" or "https", because Cloudflare's edge sets it and apps need it
// to build correct links.
func StripForwarded(h http.Header) {
	for k := range h {
		if k == "Cf-Connecting-Ip" || k == "X-Forwarded-Proto" {
			continue
		}
		if isForwardingName(k) {
			delete(h, k)
		}
	}
	if v := h.Values("X-Forwarded-Proto"); len(v) != 1 || (v[0] != "https" && v[0] != "http") {
		delete(h, "X-Forwarded-Proto")
	}
}

// stripTrailers removes every forwarding name from request trailers, with no
// exceptions: a trailer has no business carrying an address. Go fills
// r.Trailer when the body has been read to its end, so the body is wrapped and
// the trailers are cleaned again at that point, before a reverse proxy copies
// them upstream.
func stripTrailers(r *http.Request) {
	clean := func() {
		for k := range r.Trailer {
			if isForwardingName(k) {
				delete(r.Trailer, k)
			}
		}
	}
	clean()
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &trailerScrub{ReadCloser: r.Body, clean: clean}
	}
}

// trailerScrub calls clean once the wrapped body reports its end.
type trailerScrub struct {
	io.ReadCloser
	clean func()
}

func (t *trailerScrub) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if err == io.EOF {
		t.clean()
	}
	return n, err
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (g Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	StripForwarded(r.Header)
	stripTrailers(r)

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
