package sitecheck

import (
	"strings"
	"testing"
)

// target builds the Path of a test request target, failing the test if it
// does not parse.
func target(t *testing.T, raw string) Path {
	t.Helper()
	p, err := ParseTarget(raw)
	if err != nil {
		t.Fatalf("test path %q does not parse: %v", raw, err)
	}
	return p
}

func TestCheckStatic(t *testing.T) {
	cases := map[string]Verdict{
		"/":                                   Allow,
		"/index.html":                         Allow,
		"/css/site.css":                       Allow,
		"/a%20b.html":                         Allow,
		"/über.html":                          Allow,
		"/file~.txt":                          Allow,
		"/a//b":                               Allow,
		"/keyboard.html":                      Allow,
		"/pem/readme.txt":                     Allow,
		"/../win.ini":                         BadRequest,
		"/..%2fwin.ini":                       BadRequest,
		"/%2e%2e/win.ini":                     BadRequest,
		"/a/./b":                              BadRequest,
		"/..%5cwin.ini":                       BadRequest,
		"/..%5Cwin.ini":                       BadRequest,
		"/%252e%252e/win.ini":                 BadRequest,
		"/%25":                                BadRequest,
		"/SECRET~1.TXT":                       BadRequest,
		"/PROGRA~1/x":                         BadRequest,
		"/index.html::$DATA":                  BadRequest,
		"/index.html:stream":                  BadRequest,
		"/C:/Windows/win.ini":                 BadRequest,
		"/index.html.":                        BadRequest,
		"/index.html%20":                      BadRequest,
		"/dir./x":                             BadRequest,
		"/CON":                                BadRequest,
		"/con.txt":                            BadRequest,
		"/nul.txt":                            BadRequest,
		"/COM1":                               BadRequest,
		"/LPT1.log":                           BadRequest,
		"/a%00b":                              BadRequest,
		"/a%0ab":                              BadRequest,
		"/a%7fb":                              BadRequest,
		"/a%ffb":                              BadRequest,
		"/a*b":                                BadRequest,
		"/a%3fb":                              BadRequest,
		"/a%22b":                              BadRequest,
		"/a%3cb":                              BadRequest,
		"/a%7cb":                              BadRequest,
		"//evil.example/":                     BadRequest,
		"/.git/config":                        NotFound,
		"/.env":                               NotFound,
		"/.ENV":                               NotFound,
		"/.Env":                               NotFound,
		"/sub/.htaccess":                      NotFound,
		"/.well-known/x":                      NotFound,
		"/key.pem":                            NotFound,
		"/key.PEM":                            NotFound,
		"/tls/server.key":                     NotFound,
		"/cert.pfx":                           NotFound,
		"/cert.P12":                           NotFound,
		"/db.bak":                             NotFound,
		"/dump.sql":                           NotFound,
		"/WEB.CONFIG":                         NotFound,
		"/web.config":                         NotFound,
		"/Desktop.ini":                        NotFound,
		"/photos/Thumbs.db":                   NotFound,
		"/x.bak/readme.txt":                   NotFound,
		"/id_rsa":                             NotFound,
		"/keys/ID_ED25519":                    NotFound,
		"/id_ecdsa_sk":                        NotFound,
		"/ssh_host_ed25519_key":               NotFound,
		"/session.ppk":                        NotFound,
		"/vault.KDBX":                         NotFound,
		"/id_rsa.pub":                         Allow,
		"/ssh_host_rsa_key.pub":               Allow,
		"/" + strings.Repeat("a", MaxPathLen): BadRequest,
	}
	for raw, want := range cases {
		p := target(t, raw)
		if got := CheckStatic(p); got != want {
			t.Errorf("CheckStatic(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestCheckStaticRawBackslash(t *testing.T) {
	// a literal backslash on the wire never reaches url decoding as a separator
	if got := CheckStatic(target(t, `/..\win.ini`)); got != BadRequest {
		t.Fatalf("got %v", got)
	}
	for _, raw := range []string{"", "index.html", "*", "http://x/index.html"} {
		if _, err := ParseTarget(raw); err == nil {
			t.Errorf("target %q parsed", raw)
		}
	}
	// SE-25: a Path that was never built refuses
	if CheckStatic(Path{}) != BadRequest || CheckProxy(Path{}) != BadRequest {
		t.Fatal("the zero Path was allowed")
	}
}

func TestCheckProxy(t *testing.T) {
	cases := map[string]Verdict{
		"/":                   Allow,
		"/api/user:123":       Allow,
		"/items/foo.":         Allow,
		"/CON":                Allow,
		"/q%3fx":              Allow,
		"/a%25b":              Allow,
		"/../etc/passwd":      BadRequest,
		"/..%2fetc/passwd":    BadRequest,
		"/..%5cwin.ini":       BadRequest,
		"/a%00b":              BadRequest,
		"/a%0d%0aSet-Cookie:": BadRequest,
		"/.env":               NotFound,
		"/.git/HEAD":          NotFound,
		"/backup.sql":         NotFound,
		"/server.key":         NotFound,
		// Windows aliases of never-serve names (security review, Phase 1)
		"/GIT~1/config":      NotFound,
		"/ENV~1":             NotFound,
		"/SERVER~1.KEY":      NotFound,
		"/server.key.":       NotFound,
		"/server.key%20":     NotFound,
		"/server.key.%20.":   NotFound,
		"/server.key::$DATA": NotFound,
		"/web.config.":       NotFound,
		"/backup.sql::$DATA": NotFound,
		"/.env::$DATA":       NotFound,
		"/x/.git:stream/a":   NotFound,
		"/api/user:42":       Allow,
		"/v1/items~2024":     Allow,
		"/release-notes.v2~": Allow,
	}
	for raw, want := range cases {
		p := target(t, raw)
		if got := CheckProxy(p); got != want {
			t.Errorf("CheckProxy(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, n := range []string{"index.html", "img", "a b.txt"} {
		if !CheckName(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range []string{".env", "key.pem", "nul", "a:b", "x.", "SECRE~1.TXT", "web.config"} {
		if CheckName(n) {
			t.Errorf("%q allowed", n)
		}
	}
}

func TestVerdictString(t *testing.T) {
	if Allow.String() != "allow" || BadRequest.String() != "bad request" || NotFound.String() != "not found" || Verdict(9).String() != "unknown" {
		t.Fatal("verdict names changed")
	}
}

// Owner decision 12 Nov 2026: /.well-known/ may be served when a site opts
// in; nothing else changes.
func TestWellKnownOptIn(t *testing.T) {
	on := Rules{AllowWellKnown: true}
	type want struct{ static, proxy Verdict }
	cases := map[string]want{
		"/.well-known/security.txt":         {Allow, Allow},
		"/.well-known/":                     {Allow, Allow},
		"/.well-known/openid-configuration": {Allow, Allow},
		"/.well-known/.env":                 {NotFound, NotFound},
		"/.well-known/id.key":               {NotFound, NotFound},
		"/.well-known/a/.git/config":        {NotFound, NotFound},
		"/.WELL-KNOWN/security.txt":         {NotFound, NotFound},
		"/.Well-Known/security.txt":         {NotFound, NotFound},
		"/a/.well-known/security.txt":       {NotFound, NotFound},
		"/.well-known./security.txt":        {BadRequest, NotFound},
		"/.well-known%20/security.txt":      {BadRequest, NotFound},
		"/.well-known::$DATA/x":             {BadRequest, NotFound},
		"/.well-known/../.env":              {BadRequest, BadRequest},
		"/.well-known/..%2f.env":            {BadRequest, BadRequest},
		"/.well-known/SECRET~1.TXT":         {BadRequest, NotFound},
		"/.well-known/x.":                   {BadRequest, Allow},
		"/.well-knownx/a":                   {NotFound, NotFound},
	}
	for raw, w := range cases {
		p := target(t, raw)
		if got := on.Static(p); got != w.static {
			t.Errorf("Static(%q) = %v, want %v", raw, got, w.static)
		}
		if got := on.Proxy(p); got != w.proxy {
			t.Errorf("Proxy(%q) = %v, want %v", raw, got, w.proxy)
		}
	}
	for _, raw := range []string{"/.well-known/security.txt", "/.well-known/"} {
		if CheckStatic(target(t, raw)) != NotFound || CheckProxy(target(t, raw)) != NotFound {
			t.Errorf("%s allowed without the opt-in", raw)
		}
	}
}
