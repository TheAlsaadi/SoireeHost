package config

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// FuzzDecode: decoding never panics, and anything accepted re-encodes to a
// config that is accepted again unchanged and keeps the S-01 and S-10
// invariants.
func FuzzDecode(f *testing.F) {
	seed, _ := validConfig().Encode()
	f.Add(seed)
	f.Add([]byte(`{"version":1,"sites":[]}`))
	f.Add([]byte(`{"version":1,"listen":"[::1]:9000","sites":[{"id":"x","name":"x","enabled":true,"hostnames":["a.b"],"type":"proxy","proxy":{"target":"localhost:80"}}]}`))
	f.Add([]byte(`{"version":1,"sites":[{"id":"x","name":"x","type":"static","static":{"root":"C:\\a"},"response_headers":{"Referrer-Policy":""}}]}`))
	f.Add([]byte(`{"version":1,"listen":"0.0.0.0:80"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		ap, err := ParseListen(c.Listen)
		if err != nil || !IsStrictLoopback(ap.Addr()) {
			t.Fatalf("accepted non-loopback listen %q", c.Listen)
		}
		for _, s := range c.Sites {
			if s.Type == TypeProxy {
				tp, err := ParseTarget(s.Proxy.Target, s.Proxy.AllowLAN, ap.Port())
				if err != nil {
					t.Fatalf("accepted bad target %q: %v", s.Proxy.Target, err)
				}
				if a := tp.Addr(); a.IsLinkLocalUnicast() || a.IsUnspecified() || (!a.IsLoopback() && !s.Proxy.AllowLAN) {
					t.Fatalf("target %q breaks S-10", s.Proxy.Target)
				}
			}
			for _, h := range s.Hostnames {
				if strings.ToLower(h) != h {
					t.Fatalf("hostname %q not normalised", h)
				}
			}
		}
		again, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		c2, err := Decode(bytes.NewReader(again))
		if err != nil {
			t.Fatalf("re-decode of accepted config failed: %v\n%s", err, again)
		}
		again2, _ := c2.Encode()
		if !bytes.Equal(again, again2) {
			t.Fatalf("config not stable across round trip")
		}
	})
}

// FuzzHostname: anything accepted is a plain lower-case DNS name.
func FuzzHostname(f *testing.F) {
	for _, s := range []string{"example.com", "a.b.c", "xn--d.e", "1.2.3.4", "*.a.b", "A.B", "a..b", "demo.localhost", "a-.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if ValidateHostname(h) != nil {
			return
		}
		if len(h) > 253 || strings.ToLower(h) != h || !strings.Contains(h, ".") {
			t.Fatalf("accepted %q", h)
		}
		for _, r := range h {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
				t.Fatalf("accepted %q with %q", h, r)
			}
		}
		if _, err := netip.ParseAddr(h); err == nil {
			t.Fatalf("accepted IP %q", h)
		}
	})
}

// FuzzTarget: anything accepted is strict loopback, or private with the opt-in.
func FuzzTarget(f *testing.F) {
	for _, s := range []string{"127.0.0.1:1", "[::1]:2", "10.0.0.1:80", "169.254.169.254:80", "[::ffff:127.0.0.1]:1", "[fe80::1%1]:1", "localhost:1"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, s string, lan bool) {
		ap, err := ParseTarget(s, lan, 8787)
		if err != nil {
			return
		}
		a := ap.Addr()
		if ap.Port() == 0 || a.Zone() != "" || a.Is4In6() {
			t.Fatalf("accepted %q -> %v", s, ap)
		}
		if a.IsLoopback() {
			if !IsStrictLoopback(a) || ap.Port() == 8787 {
				t.Fatalf("accepted %q", s)
			}
			return
		}
		if !lan || !a.IsPrivate() {
			t.Fatalf("accepted non-loopback %q (lan=%v)", s, lan)
		}
	})
}

// FuzzRootSyntax: anything accepted is a cleaned drive path with no Windows
// path tricks.
func FuzzRootSyntax(f *testing.F) {
	for _, s := range []string{`C:\Sites\blog`, `C:\`, `\\srv\s`, `C:\a\..\b`, `C:\PROGRA~1`, `C:\a:b`, `C:\a.`, `C:\nul`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, root string) {
		if ValidateRootSyntax(root) != nil {
			return
		}
		if strings.HasPrefix(root, `\\`) || strings.Count(root, ":") != 1 || strings.Contains(root, `\\`) ||
			strings.HasSuffix(root, `\`) || strings.Contains(root, "/") {
			t.Fatalf("accepted %q", root)
		}
		for comp := range strings.SplitSeq(root[3:], `\`) {
			if comp == ".." || comp == "." || strings.HasSuffix(comp, ".") || strings.HasSuffix(comp, " ") ||
				IsReservedDeviceName(comp) || HasShortNameMarker(comp) {
				t.Fatalf("accepted %q (component %q)", root, comp)
			}
		}
	})
}
