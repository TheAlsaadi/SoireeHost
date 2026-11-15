package worker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// GOE-15: header stripping and request-target handling, tested on the guard
// itself rather than only through Caddy.
func TestStripForwardedTable(t *testing.T) {
	h := http.Header{}
	for _, k := range []string{"X-Forwarded-For", "X_Forwarded_For", "Forwarded", "X-Real-Ip", "True-Client-Ip",
		"X-Client-IP", "Proxy-Client-IP", "X-Azure-ClientIP", "Cf-Connecting-Ipv6", "X-Envoy-External-Address",
		"Remote-Addr", "X-Forwarded-Host"} {
		h.Set(k, "6.6.6.6")
	}
	h.Set("Cf-Connecting-Ip", "203.0.113.7")
	h.Set("X-Forwarded-Proto", "https")
	h.Set("Accept", "text/html")
	h.Set("X-Request-Id", "abc")
	StripForwarded(h)
	want := map[string]bool{"Cf-Connecting-Ip": true, "X-Forwarded-Proto": true, "Accept": true, "X-Request-Id": true}
	for k := range h {
		if !want[k] {
			t.Errorf("%s survived", k)
		}
	}
	for k := range want {
		if h.Get(k) == "" {
			t.Errorf("%s was removed", k)
		}
	}
	for _, v := range [][]string{{"gopher"}, {"https", "http"}, {"HTTPS"}, {""}} {
		h := http.Header{"X-Forwarded-Proto": v}
		StripForwarded(h)
		if len(h) != 0 {
			t.Errorf("X-Forwarded-Proto %q kept", v)
		}
	}
}

// FuzzStripForwarded: after stripping, no header can claim another address,
// except Cf-Connecting-Ip and an exact X-Forwarded-Proto.
func FuzzStripForwarded(f *testing.F) {
	for _, s := range []string{"X-Forwarded-For", "x_real_ip", "Cf-Connecting-Ip", "X-Forwarded-Proto", "Accept", "Some-Client-IPv6"} {
		f.Add(s, "1.2.3.4")
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		h := http.Header{}
		h[name] = []string{value}
		h[http.CanonicalHeaderKey(name)] = []string{value}
		StripForwarded(h)
		for k, vs := range h {
			switch k {
			case "Cf-Connecting-Ip":
			case "X-Forwarded-Proto":
				if len(vs) != 1 || (vs[0] != "http" && vs[0] != "https") {
					t.Fatalf("X-Forwarded-Proto %q kept", vs)
				}
			default:
				if isForwardingName(k) {
					t.Fatalf("forwarding header %q kept", k)
				}
			}
		}
	})
}

func TestGuardRefusesTargets(t *testing.T) {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	status := func(g Guard, target string) int {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.RequestURI = target
		// as Go's server parses a request target: no ".." resolution
		if u, err := url.ParseRequestURI(target); err == nil {
			r.URL = u
		}
		rec := httptest.NewRecorder()
		err := g.ServeHTTP(rec, r, next)
		var he caddyhttp.HandlerError
		if errors.As(err, &he) {
			return he.StatusCode
		}
		return rec.Code
	}
	for _, mode := range []string{"static", "proxy"} {
		g := Guard{Mode: mode}
		for _, tc := range []struct {
			target string
			want   int
		}{
			{"/index.html", 200},
			{"/a?b=c", 200},
			{"http://blog.example.com/index.html", 400}, // R-13
			{"*", 400},
			{"/index.html#frag", 400}, // R-19
			{"/p?a=1#&token=S", 400},
			{"/.env", 404},
			{"/../x", 400},
		} {
			if got := status(g, tc.target); got != tc.want {
				t.Errorf("%s %q: got %d, want %d", mode, tc.target, got, tc.want)
			}
		}
	}
	// SE-25: the path the next handler acts on must be the one the target
	// decodes to; a request whose path was changed after parsing is refused
	for _, mode := range []string{"static", "proxy"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/index.html", nil)
		r.RequestURI = "/index.html"
		r.URL.Path = "/.env"
		err := Guard{Mode: mode}.ServeHTTP(httptest.NewRecorder(), r, next)
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) || he.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: a path that differs from its target got %v", mode, err)
		}
	}
	// SE-26: a guard with no mode, or an unknown one, refuses everything
	for _, g := range []Guard{{}, {Mode: "Static"}, {Mode: "admin"}} {
		if got := status(g, "/index.html"); got != 400 {
			t.Errorf("guard %+v let a request through: %d", g, got)
		}
	}
	if strings.Contains(Guard{}.Mode, "x") {
		t.Fatal("unreachable")
	}
}
