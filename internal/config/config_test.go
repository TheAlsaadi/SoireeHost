package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func validStatic() Site {
	return Site{
		ID: "blog", Name: "Blog", Enabled: true,
		Hostnames: []string{"blog.example.com"},
		Type:      TypeStatic,
		Static:    &Static{Root: `C:\Sites\blog`},
	}
}

func validProxy() Site {
	return Site{
		ID: "app", Name: "App", Enabled: true,
		Hostnames: []string{"app.example.com"},
		Type:      TypeProxy,
		Proxy:     &Proxy{Target: "127.0.0.1:3000"},
	}
}

func validConfig() Config {
	c := Default()
	c.Sites = []Site{validStatic(), validProxy()}
	c.Normalize()
	return c
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("sample config invalid: %v", err)
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	c := validConfig()
	data, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Sites[0].MaxBodyBytes != DefaultMaxBodyBytes || got.Sites[1].RateLimitPerMinute != DefaultRateLimitPerMinute {
		t.Fatalf("defaults not applied: %+v", got.Sites)
	}
}

func TestDecodeStrict(t *testing.T) {
	cases := map[string]string{
		"unknown field":   `{"version":1,"listen":"127.0.0.1:8787","sites":[],"admin":true}`,
		"trailing data":   `{"version":1,"sites":[]} {}`,
		"not an object":   `[]`,
		"wrong version":   `{"version":2,"sites":[]}`,
		"empty":           ``,
		"unknown in site": `{"version":1,"sites":[{"id":"a","name":"a","type":"static","static":{"root":"C:\\x"},"port_forward":true}]}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(in)); err == nil {
				t.Fatalf("accepted %q", in)
			}
		})
	}
	big := `{"version":1,"sites":[],"listen":"` + strings.Repeat("a", MaxConfigBytes) + `"}`
	if _, err := Decode(strings.NewReader(big)); err == nil {
		t.Fatal("accepted oversized config")
	}
}

// S-03: there is no setting that exposes a site other than through the tunnel.
func TestSchemaHasNoExposureSetting(t *testing.T) {
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(data))
	for _, banned := range []string{"port_forward", "public", "bind", "0.0.0.0", "upnp", "admin"} {
		if strings.Contains(lower, banned) {
			t.Errorf("config schema contains %q", banned)
		}
	}
}

// S-01: config validation rejects any non-loopback listener.
func TestParseListen(t *testing.T) {
	good := []string{"127.0.0.1:8787", "[::1]:8787", "127.0.0.1:1024", "127.0.0.1:65535"}
	bad := []string{
		"", ":8787", "0.0.0.0:8787", "[::]:8787", "localhost:8787", "192.168.1.5:8787",
		"127.0.0.2:8787", "[::ffff:127.0.0.1]:8787", "[fe80::1%eth0]:8787", "127.0.0.1:80",
		"127.0.0.1:0", "127.0.0.1", "127.0.0.1:65536", "10.0.0.1:8787", "[::1%1]:8787",
	}
	for _, s := range good {
		if _, err := ParseListen(s); err != nil {
			t.Errorf("rejected %q: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ParseListen(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

// S-10: proxy targets.
func TestParseTarget(t *testing.T) {
	type tc struct {
		target   string
		allowLAN bool
		ok       bool
	}
	cases := []tc{
		{"127.0.0.1:3000", false, true},
		{"[::1]:3000", false, true},
		{"127.0.0.1:8787", false, false}, // own port
		{"[::1]:8787", false, false},     // own port
		{"localhost:3000", false, false}, // must be normalised first
		{"127.0.0.2:3000", false, false},
		{"192.168.1.10:80", false, false},
		{"192.168.1.10:80", true, true},
		{"10.1.2.3:8080", true, true},
		{"172.16.0.1:80", true, true},
		{"[fd00::1]:80", true, true},
		{"169.254.169.254:80", true, false}, // cloud metadata, link-local
		{"[fe80::1]:80", true, false},
		{"[::ffff:169.254.169.254]:80", true, false},
		{"0.0.0.0:80", true, false},
		{"[::]:80", true, false},
		{"8.8.8.8:53", true, false},
		{"100.64.0.1:80", true, false},
		{"224.0.0.1:80", true, false},
		{"255.255.255.255:80", true, false},
		{"example.com:80", true, false},
		{"127.0.0.1:0", false, false},
		{"127.0.0.1:65536", false, false},
		{"127.0.0.1:+80", false, false},
		{"127.0.0.1:0080", false, false},
		{"127.0.0.1", false, false},
		{"http://127.0.0.1:3000", false, false},
		{"[fe80::1%eth0]:80", true, false},
		{"", false, false},
	}
	for _, c := range cases {
		_, err := ParseTarget(c.target, c.allowLAN, 8787)
		if (err == nil) != c.ok {
			t.Errorf("ParseTarget(%q, lan=%v) err=%v, want ok=%v", c.target, c.allowLAN, err, c.ok)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"localhost:3000":           "127.0.0.1:3000",
		"LocalHost:3000":           "127.0.0.1:3000",
		"[::ffff:127.0.0.1]:3000":  "127.0.0.1:3000",
		"[::1]:3000":               "[::1]:3000",
		"127.0.0.1:3000":           "127.0.0.1:3000",
		"not a target":             "not a target",
		"[0:0:0:0:0:0:0:1]:3000":   "[::1]:3000",
		"[::ffff:192.168.1.1]:443": "192.168.1.1:443",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// S-06: hostname rules.
func TestValidateHostname(t *testing.T) {
	good := []string{"example.com", "a.b.c.example.com", "xn--bcher-kva.example", "x1.io", "demo.localhost", "abc-def.trycloudflare.com"}
	bad := []string{
		"", "localhost", "Example.com", "*.example.com", "example.com.", ".example.com", "a..b",
		"-a.com", "a-.com", "a_b.com", "1.2.3.4", "example.com:443", "exa mple.com", "ex\x00.com",
		"bücher.example", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com",
		"[::1]", "a.123",
	}
	for _, h := range good {
		if err := ValidateHostname(h); err != nil {
			t.Errorf("rejected %q: %v", h, err)
		}
	}
	for _, h := range bad {
		if err := ValidateHostname(h); err == nil {
			t.Errorf("accepted %q", h)
		}
	}
}

// S-11 and S-13: root syntax.
func TestValidateRootSyntax(t *testing.T) {
	good := []string{`C:\Sites\blog`, `D:\www`, `c:\x`, `C:\Users\me\Documents\site`}
	bad := []string{
		``, `C:\`, `C:`, `C:Sites`, `\Sites`, `Sites\blog`, `\\server\share\site`, `\\?\C:\site`, `\\.\C:\site`,
		`//server/share`, `C:\Sites\..\Windows`, `C:\Sites\.\blog`, `C:\Sites\blog\`, `C:\Sites\\blog`,
		`C:\Sites\blog.`, `C:\Sites\blog `, `C:\Sites\CON`, `C:\Sites\nul.txt`, `C:\Sites\COM1`,
		`C:\PROGRA~1\site`, `C:\Sites\blog:stream`, `C:\Sites\a*b`, "C:\\Sites\\a\x01b",
		`C:\Users\me\AppData\Roaming\x`, `C:\Users\me\.ssh`, `C:/Sites/blog`, "C:\\\xff",
		`1:\Sites`, `C:\$Recycle.Bin\S-1-5-21`, `D:\System Volume Information`, `C:\Windows.old\Users`,
		`C:\ProgramData\ssh`, `E:\Recovery`, `C:\$WINDOWS.~BT\Sources`,
	}
	for _, r := range good {
		if err := ValidateRootSyntax(r); err != nil {
			t.Errorf("rejected %q: %v", r, err)
		}
	}
	for _, r := range bad {
		if err := ValidateRootSyntax(r); err == nil {
			t.Errorf("accepted %q", r)
		}
	}
}

func TestReservedAndShortNames(t *testing.T) {
	for _, n := range []string{"CON", "con", "Nul.txt", "nul .txt", "COM1", "lpt9.log", "COM¹", "CONIN$", "aux.tar.gz"} {
		if !IsReservedDeviceName(n) {
			t.Errorf("%q not reserved", n)
		}
	}
	for _, n := range []string{"console", "nullable", "com10", "index.html", "lpt"} {
		if IsReservedDeviceName(n) {
			t.Errorf("%q reported reserved", n)
		}
	}
	for _, n := range []string{"SECRET~1.TXT", "PROGRA~1", "a~9"} {
		if !HasShortNameMarker(n) {
			t.Errorf("%q not flagged", n)
		}
	}
	for _, n := range []string{"file~.txt", "~tmp", "a~b"} {
		if HasShortNameMarker(n) {
			t.Errorf("%q flagged", n)
		}
	}
}

func TestSiteValidation(t *testing.T) {
	mut := func(f func(c *Config)) Config {
		c := validConfig()
		f(&c)
		return c
	}
	cases := map[string]Config{
		"bad id":                mut(func(c *Config) { c.Sites[0].ID = "Blog!" }),
		"id leading dash":       mut(func(c *Config) { c.Sites[0].ID = "-x" }),
		"duplicate id":          mut(func(c *Config) { c.Sites[1].ID = "blog" }),
		"empty name":            mut(func(c *Config) { c.Sites[0].Name = "  " }),
		"bidi name":             mut(func(c *Config) { c.Sites[0].Name = "abc\u202Etxt.exe" }),
		"control name":          mut(func(c *Config) { c.Sites[0].Name = "a\nb" }),
		"long name":             mut(func(c *Config) { c.Sites[0].Name = strings.Repeat("x", 65) }),
		"duplicate host":        mut(func(c *Config) { c.Sites[1].Hostnames = []string{"blog.example.com"} }),
		"duplicate host inside": mut(func(c *Config) { c.Sites[0].Hostnames = []string{"a.example.com", "a.example.com"} }),
		"bad type":              mut(func(c *Config) { c.Sites[0].Type = "php" }),
		"static without static": mut(func(c *Config) { c.Sites[0].Static = nil }),
		"static with proxy":     mut(func(c *Config) { c.Sites[0].Proxy = &Proxy{Target: "127.0.0.1:1"} }),
		"proxy with static":     mut(func(c *Config) { c.Sites[1].Static = &Static{Root: `C:\x`} }),
		"proxy without proxy":   mut(func(c *Config) { c.Sites[1].Proxy = nil }),
		"proxy to own port":     mut(func(c *Config) { c.Sites[1].Proxy.Target = "127.0.0.1:8787" }),
		"proxy to LAN no optin": mut(func(c *Config) { c.Sites[1].Proxy.Target = "192.168.0.2:80" }),
		// R-06: every port SoiréeHost listens on is refused as a target
		"proxy to metrics port": mut(func(c *Config) { c.Sites[1].Proxy.Target = "127.0.0.1:20241" }),
		"proxy to share port": mut(func(c *Config) {
			c.Sites[0].QuickShare = &QuickShare{Port: 8788, MetricsPort: 20242}
			c.Sites[1].Proxy.Target = "[::1]:8788"
		}),
		"proxy to share metrics": mut(func(c *Config) {
			c.Sites[0].QuickShare = &QuickShare{Port: 8788, MetricsPort: 20242}
			c.Sites[1].Proxy.Target = "127.0.0.1:20242"
		}),
		"share on listen port":   mut(func(c *Config) { c.Sites[0].QuickShare = &QuickShare{Port: 8787, MetricsPort: 20242} }),
		"share on metrics port":  mut(func(c *Config) { c.Sites[0].QuickShare = &QuickShare{Port: 20241, MetricsPort: 20242} }),
		"share ports equal":      mut(func(c *Config) { c.Sites[0].QuickShare = &QuickShare{Port: 9000, MetricsPort: 9000} }),
		"share low port":         mut(func(c *Config) { c.Sites[0].QuickShare = &QuickShare{Port: 80, MetricsPort: 20242} }),
		"share port too big":     mut(func(c *Config) { c.Sites[0].QuickShare = &QuickShare{Port: 70000, MetricsPort: 20242} }),
		"metrics port zero left": mut(func(c *Config) { c.Tunnel.MetricsPort = 80 }),
		"two shares same port": mut(func(c *Config) {
			c.Sites[0].QuickShare = &QuickShare{Port: 8788, MetricsPort: 20242}
			c.Sites[1].QuickShare = &QuickShare{Port: 8788, MetricsPort: 20243}
		}),
		"body too small": mut(func(c *Config) { c.Sites[0].MaxBodyBytes = 1 }),
		"body negative":  mut(func(c *Config) { c.Sites[0].MaxBodyBytes = -1 }),
		"rate negative":  mut(func(c *Config) { c.Sites[0].RateLimitPerMinute = -1 }),
		"rate huge":      mut(func(c *Config) { c.Sites[0].RateLimitPerMinute = 1 << 30 }),
		"unknown header": mut(func(c *Config) { c.Sites[0].ResponseHeaders = map[string]string{"Server": "x"} }),
		"header CRLF": mut(func(c *Config) {
			c.Sites[0].ResponseHeaders = map[string]string{"Referrer-Policy": "a\r\nSet-Cookie: x"}
		}),
		"header non-ascii":  mut(func(c *Config) { c.Sites[0].ResponseHeaders = map[string]string{"Referrer-Policy": "é"} }),
		"listen public":     mut(func(c *Config) { c.Listen = "0.0.0.0:8787" }),
		"header bytes tiny": mut(func(c *Config) { c.Server.MaxHeaderBytes = 10 }),
		"timeouts inverted": mut(func(c *Config) { c.Server.ReadHeaderTimeoutSeconds = 100; c.Server.ReadTimeoutSeconds = 10 }),
		"timeout huge":      mut(func(c *Config) { c.Server.IdleTimeoutSeconds = 99999 }),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error has no field path: %v", err)
			}
		})
	}
}

// TestTooManyQuickShares: at most MaxQuickShares sites are shared at once,
// because the tunnel launcher's job allows only that many cloudflared
// processes (ADR-0007).
func TestTooManyQuickShares(t *testing.T) {
	c := validConfig()
	for i := range MaxQuickShares + 1 {
		c.Sites = append(c.Sites, Site{ID: fmt.Sprintf("s%d", i), Name: "s", Type: TypeProxy,
			Proxy:        &Proxy{Target: fmt.Sprintf("127.0.0.1:%d", 3000+i)},
			QuickShare:   &QuickShare{Port: QuickSharePortMin + i, MetricsPort: QuickShareMetricsMin + i},
			MaxBodyBytes: DefaultMaxBodyBytes, RateLimitPerMinute: 1})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("five shares accepted: %v", err)
	}
	c.Sites = c.Sites[:len(c.Sites)-1]
	if err := c.Validate(); err != nil {
		t.Fatalf("four shares refused: %v", err)
	}
	if got := len(c.OwnPorts()); got != 2+2*MaxQuickShares {
		t.Fatalf("OwnPorts has %d ports, want %d", got, 2+2*MaxQuickShares)
	}
}

// TestOldConfigGetsTunnelDefaults: a config saved before Phase 3 has no
// tunnel block; it decodes with the default metrics port and online.
func TestOldConfigGetsTunnelDefaults(t *testing.T) {
	c, err := Decode(strings.NewReader(`{"version":1,"listen":"127.0.0.1:8787","sites":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tunnel.MetricsPort != DefaultMetricsPort || c.Tunnel.Offline {
		t.Fatalf("tunnel = %+v", c.Tunnel)
	}
}

func TestDuplicateHostnameInsideOneSite(t *testing.T) {
	c := validConfig()
	c.Sites[0].Hostnames = []string{"a.example.com", "a.example.com"}
	err := c.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	if msg := err.Error(); strings.Contains(msg, "\n") || strings.Contains(msg, "already used by site") {
		t.Fatalf("want one 'duplicate hostname' problem, got:\n%s", msg)
	}
}

func TestLANWarning(t *testing.T) {
	c := validConfig()
	if len(c.Warnings()) != 0 {
		t.Fatalf("unexpected warnings: %v", c.Warnings())
	}
	c.Sites[1].Proxy = &Proxy{Target: "192.168.0.2:80", AllowLAN: true}
	if err := c.Validate(); err != nil {
		t.Fatalf("LAN with opt-in rejected: %v", err)
	}
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0], "local network") {
		t.Fatalf("warnings = %v", w)
	}
}

func TestEffectiveHeaders(t *testing.T) {
	s := validStatic()
	h := s.EffectiveHeaders()
	if h["X-Content-Type-Options"] != "nosniff" || h["Content-Security-Policy"] != "frame-ancestors 'none'" ||
		h["Referrer-Policy"] != "strict-origin-when-cross-origin" || h["Permissions-Policy"] == "" {
		t.Fatalf("defaults wrong: %v", h)
	}
	s.ResponseHeaders = map[string]string{"Content-Security-Policy": "", "Referrer-Policy": "no-referrer"}
	h = s.EffectiveHeaders()
	if _, ok := h["Content-Security-Policy"]; ok {
		t.Fatal("empty override did not remove header")
	}
	if h["Referrer-Policy"] != "no-referrer" {
		t.Fatal("override not applied")
	}
	if DefaultHeaders()["X-Content-Type-Options"] != "nosniff" {
		t.Fatal("defaults were mutated")
	}
}

func TestNormalizeLowercasesHostnames(t *testing.T) {
	c := Default()
	s := validStatic()
	s.Hostnames = []string{"Blog.Example.COM"}
	c.Sites = []Site{s}
	c.Normalize()
	if c.Sites[0].Hostnames[0] != "blog.example.com" {
		t.Fatalf("got %q", c.Sites[0].Hostnames[0])
	}
}
