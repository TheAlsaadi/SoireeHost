package sitecheck

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// FuzzCheckStatic: whatever a client sends, a path that is allowed can never
// name a hidden or blocked file or use a Windows path trick.
func FuzzCheckStatic(f *testing.F) {
	for _, s := range []string{
		"/", "/index.html", "/../x", "/..%2fx", "/%252e%252e/", "/SECRET~1.TXT", "/a::$DATA", "/a.", "/a%20",
		"/CON", "/.git/config", "/.ENV", "/key.PEM", "/a%5cb", "/%c0%ae%c0%ae/", "//x", "/x/%2e/y",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Add("/.well-known/security.txt", true)
	f.Add("/.well-known/.env", true)
	f.Fuzz(func(t *testing.T, raw string, wellKnown bool) {
		u, err := url.ParseRequestURI(raw)
		if err != nil {
			return
		}
		dec := u.Path
		rawPath := raw
		if i := strings.IndexByte(rawPath, '?'); i >= 0 {
			rawPath = rawPath[:i]
		}
		if (Rules{AllowWellKnown: wellKnown}).Static(dec, rawPath) != Allow {
			return
		}
		if !utf8.ValidString(dec) || !strings.HasPrefix(dec, "/") || strings.HasPrefix(dec, "//") || strings.ContainsAny(dec, "\\:*?\"<>|\x00") {
			t.Fatalf("allowed %q (decoded %q)", raw, dec)
		}
		for _, r := range dec {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("allowed control char in %q", dec)
			}
		}
		for i, seg := range strings.Split(dec[1:], "/") {
			if seg == "" || (wellKnown && i == 0 && seg == WellKnown) {
				continue
			}
			if seg == "." || seg == ".." || strings.HasPrefix(seg, ".") || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") ||
				config.IsReservedDeviceName(seg) || config.HasShortNameMarker(seg) || hiddenOrBlocked(seg) {
				t.Fatalf("allowed %q (segment %q)", raw, seg)
			}
		}
	})
}

// FuzzCheckProxy: an allowed proxy path never traverses or carries control
// characters or backslashes.
func FuzzCheckProxy(f *testing.F) {
	for _, s := range []string{"/", "/api", "/../x", "/a%00", "/.env", "/a%5c", "/a%0d%0a"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Add("/.well-known/openid-configuration", true)
	f.Fuzz(func(t *testing.T, raw string, wellKnown bool) {
		u, err := url.ParseRequestURI(raw)
		if err != nil {
			return
		}
		if (Rules{AllowWellKnown: wellKnown}).Proxy(u.Path, u.EscapedPath()) != Allow {
			return
		}
		if strings.ContainsAny(u.Path, "\\\x00\r\n") {
			t.Fatalf("allowed %q", raw)
		}
		for i, seg := range strings.Split(u.Path[1:], "/") {
			if wellKnown && i == 0 && seg == WellKnown {
				continue
			}
			if seg == "." || seg == ".." || strings.HasPrefix(seg, ".") || (seg != "" && hiddenOrBlocked(windowsName(seg))) {
				t.Fatalf("allowed %q", raw)
			}
		}
	})
}
