package config

import (
	"slices"
	"strings"
	"testing"
)

// SE-28: an empty header value is refused; removing a header is explicit.
func TestRemoveHeadersValidation(t *testing.T) {
	c := Default()
	s := validStatic()
	s.ResponseHeaders = map[string]string{"Referrer-Policy": ""}
	c.Sites = []Site{s}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "remove_headers") {
		t.Fatalf("empty header value: %v", err)
	}
	for _, bad := range [][]string{{"Server"}, {"Referrer-Policy", "Referrer-Policy"}} {
		s := validStatic()
		s.RemoveHeaders = bad
		c.Sites = []Site{s}
		c.Normalize()
		if err := c.Validate(); err == nil {
			t.Errorf("remove_headers %v accepted", bad)
		}
	}
	s = validStatic()
	s.ResponseHeaders = map[string]string{"Referrer-Policy": "no-referrer"}
	s.RemoveHeaders = []string{"Referrer-Policy"}
	c.Sites = []Site{s}
	c.Normalize()
	if err := c.Validate(); err == nil {
		t.Error("a header both set and removed was accepted")
	}
	s.ResponseHeaders = nil
	c.Sites = []Site{s}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Errorf("valid removal refused: %v", err)
	}
}

// SE-28: a saved config from an earlier version keeps its behaviour: an
// empty value becomes an explicit removal.
func TestMigrateLegacyEmptyHeader(t *testing.T) {
	in := `{"version":1,"listen":"127.0.0.1:8787","server":{"max_header_bytes":65536,"read_header_timeout_seconds":10,"read_timeout_seconds":300,"idle_timeout_seconds":120},` +
		`"tunnel":{"offline":false,"metrics_port":20300},"sites":[{"id":"a","name":"A","enabled":true,"hostnames":["a.example.com"],"type":"proxy",` +
		`"proxy":{"target":"127.0.0.1:3000","allow_lan":false},"max_body_bytes":0,"rate_limit_per_minute":0,"allow_well_known":false,` +
		`"response_headers":{"Content-Security-Policy":"","Referrer-Policy":"no-referrer"},"firewall":{"mode":"","paranoia_level":0}}]}`
	c, err := Decode(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sites[0]
	if !slices.Equal(s.RemoveHeaders, []string{"Content-Security-Policy"}) || s.ResponseHeaders["Referrer-Policy"] != "no-referrer" {
		t.Fatalf("migrated site: %+v", s)
	}
	if _, sent := s.EffectiveHeaders()["Content-Security-Policy"]; sent {
		t.Fatal("migration changed what is sent")
	}
}

// SE-28: weakened header values and the opt-ins raise warnings; the
// defaults and stricter values do not.
func TestHeaderAndOptInWarnings(t *testing.T) {
	cases := []struct {
		name, value string
		weak        bool
	}{
		{"Content-Security-Policy", "frame-ancestors 'none'", false},
		{"Content-Security-Policy", "frame-ancestors 'self'", false},
		{"Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'", false},
		{"Content-Security-Policy", "frame-ancestors *", true},
		{"Content-Security-Policy", "frame-ancestors https://a.example.com", true},
		{"Content-Security-Policy", "default-src 'self'", true},
		{"Content-Security-Policy", "frame-ancestors", true},
		{"X-Content-Type-Options", "nosniff", false},
		{"X-Content-Type-Options", "sniff", true},
		{"Referrer-Policy", "no-referrer", false},
		{"Referrer-Policy", "unsafe-url", true},
		{"Referrer-Policy", "no-referrer, no-referrer-when-downgrade", true},
		{"Permissions-Policy", "camera=()", false},
	}
	for _, tc := range cases {
		if got := weakValue(tc.name, tc.value); got != tc.weak {
			t.Errorf("%s: %q weak=%v, want %v", tc.name, tc.value, got, tc.weak)
		}
	}
	s := validStatic()
	if w := s.WeakenedHeaders(); len(w) != 0 {
		t.Fatalf("defaults reported weak: %v", w)
	}
	s.RemoveHeaders = []string{"X-Content-Type-Options"}
	s.ResponseHeaders = map[string]string{"Content-Security-Policy": "frame-ancestors *"}
	s.Static.DirectoryListing = true
	s.AllowWellKnown = true
	c := Config{Sites: []Site{s}}
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"does not send X-Content-Type-Options", "weaker Content-Security-Policy", "lists the files", "/.well-known/"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	added := HeaderWeakenings(Config{Sites: []Site{validStatic()}}, c)
	if got := added[s.ID]; !slices.Equal(got, []string{"Content-Security-Policy", "X-Content-Type-Options"}) {
		t.Fatalf("header weakenings: %v", added)
	}
	if again := HeaderWeakenings(c, c); len(again) != 0 {
		t.Fatalf("an unchanged site counted as weakening: %v", again)
	}
}
