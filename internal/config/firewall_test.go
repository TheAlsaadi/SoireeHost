package config

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// S-14: every site starts in Block mode at paranoia level 1, including sites
// saved before the firewall existed.
func TestFirewallDefaults(t *testing.T) {
	old := `{"version":1,"listen":"127.0.0.1:8787","server":{},"tunnel":{},"sites":[
		{"id":"blog","name":"Blog","enabled":true,"hostnames":["blog.example.com"],"type":"proxy",
		 "proxy":{"target":"127.0.0.1:3000"},"max_body_bytes":0,"rate_limit_per_minute":0,"allow_well_known":false}]}`
	c, err := Decode(strings.NewReader(old))
	if err != nil {
		t.Fatal(err)
	}
	if fw := c.Sites[0].Firewall; fw.Mode != FirewallBlock || fw.ParanoiaLevel != 1 {
		t.Fatalf("old site loads as %+v, want block at level 1", fw)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("a default site has warnings: %v", w)
	}
}

func TestFirewallValidation(t *testing.T) {
	for _, fw := range []Firewall{{Mode: "On"}, {Mode: "BLOCK"}, {Mode: "detect", ParanoiaLevel: 5}, {ParanoiaLevel: -1}} {
		c := validConfig()
		c.Sites[0].Firewall = fw
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "firewall") {
			t.Errorf("%+v accepted: %v", fw, err)
		}
	}
	for _, fw := range []Firewall{{}, {Mode: FirewallOff}, {Mode: FirewallDetect, ParanoiaLevel: 4}, {Mode: FirewallBlock, ParanoiaLevel: 2}} {
		c := validConfig()
		c.Sites[0].Firewall = fw
		if err := c.Validate(); err != nil {
			t.Errorf("%+v refused: %v", fw, err)
		}
	}
}

// S-14: Off and Detect only show standing warnings, and so does a Block
// site whose body limit is above what the firewall inspects.
func TestFirewallWarnings(t *testing.T) {
	c := validConfig()
	c.Sites[0].Firewall.Mode = FirewallOff
	if w := strings.Join(c.Warnings(), " "); !strings.Contains(w, "turned off") {
		t.Fatalf("Off: warnings %q", w)
	}
	c.Sites[0].Firewall.Mode = FirewallDetect
	if w := strings.Join(c.Warnings(), " "); !strings.Contains(w, "Detect only") {
		t.Fatalf("Detect only: warnings %q", w)
	}
	c.Sites[0].Firewall.Mode = FirewallBlock
	c.Sites[0].MaxBodyBytes = 100 << 20
	if w := strings.Join(c.Warnings(), " "); !strings.Contains(w, "refused") {
		t.Fatalf("large body limit: warnings %q", w)
	}
}

func TestFirewallWeakenings(t *testing.T) {
	site := func(id, mode string) Site { return Site{ID: id, Firewall: Firewall{Mode: mode}} }
	cur := Config{Sites: []Site{site("a", FirewallBlock), site("b", FirewallDetect), site("c", FirewallOff)}}
	for _, tc := range []struct {
		next []Site
		want []string
	}{
		{[]Site{site("a", FirewallBlock), site("b", FirewallDetect), site("c", FirewallOff)}, nil},
		{[]Site{site("a", "")}, nil},
		{[]Site{site("a", FirewallDetect)}, []string{"a"}},
		{[]Site{site("a", FirewallOff), site("b", FirewallOff)}, []string{"a", "b"}},
		{[]Site{site("b", FirewallBlock), site("c", FirewallDetect)}, nil},
		{[]Site{site("new", FirewallBlock)}, nil},
		{[]Site{site("new", FirewallDetect), site("new2", FirewallOff)}, []string{"new", "new2"}},
	} {
		if got := FirewallWeakenings(cur, Config{Sites: tc.next}); !slices.Equal(got, tc.want) {
			t.Errorf("next %+v: got %v, want %v", tc.next, got, tc.want)
		}
	}
}

func TestFirewallEncodesExplicitly(t *testing.T) {
	c := validConfig()
	c.Normalize()
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"mode": "block"`)) || !bytes.Contains(b, []byte(`"paranoia_level": 1`)) {
		t.Fatalf("firewall setting not written: %s", b)
	}
}
