package worker

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// TestQuickShareHostGate (S-06, ADR-0007): a quick share's port answers 404
// for every hostname until cloudflared's is known, then serves only that one
// hostname, and only that site; the main listener never serves it.
func TestQuickShareHostGate(t *testing.T) {
	sharePort := freePort(t)
	h := startHarness(t, func(c *config.Config) {
		c.Sites[0].QuickShare = &config.QuickShare{Port: sharePort, MetricsPort: 20242}
	})
	share := &harness{addr: fmt.Sprintf("127.0.0.1:%d", sharePort)}
	const assigned = "seasonal-deck-organisms-sf.trycloudflare.com"

	// before cloudflared has a hostname: 404 for everything
	for _, host := range []string{assigned, "blog.example.com", "other.trycloudflare.com", share.addr} {
		if r := share.get(t, host, "/"); r.status != 404 || strings.Contains(r.body, "INDEX-OK") {
			t.Errorf("before assignment, Host %q: %d %q", host, r.status, r.body)
		}
	}

	if err := Load(h.cfg, Options{LogDir: h.logDir, QuickHosts: map[string]string{"blog": assigned}}); err != nil {
		t.Fatal(err)
	}
	if r := share.get(t, assigned, "/"); r.status != 200 || r.body != "INDEX-OK" {
		t.Fatalf("assigned host: %d %q", r.status, r.body)
	}
	checkSecurityHeaders(t, "quick share", share.get(t, assigned, "/").header)
	// the site's rules still apply on the share
	if r := share.get(t, assigned, "/.env"); r.status != 404 || strings.Contains(r.body, secretMarker) {
		t.Errorf("dotfile through the share: %d %q", r.status, r.body)
	}
	for _, host := range []string{"blog.example.com", "app.example.com", "other.trycloudflare.com", "evil.example", "127.0.0.1", share.addr,
		assigned + ".evil.example", "x." + assigned} {
		if r := share.get(t, host, "/"); r.status != 404 || strings.Contains(r.body, "INDEX-OK") {
			t.Errorf("share port, Host %q: %d %q", host, r.status, r.body)
		}
	}
	// the main listener knows nothing of the quick share hostname
	if r := h.get(t, assigned, "/"); r.status != 404 {
		t.Errorf("main listener served the quick share host: %d", r.status)
	}
	if r := h.get(t, "blog.example.com", "/"); r.status != 200 {
		t.Errorf("main listener stopped serving the site: %d", r.status)
	}
}

func TestQuickShareConfig(t *testing.T) {
	c := config.Default()
	c.Sites = []config.Site{
		{ID: "blog", Name: "Blog", Enabled: true, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3000"},
			QuickShare: &config.QuickShare{Port: 8788, MetricsPort: 20242}},
		{ID: "off", Name: "Off", Enabled: false, Type: config.TypeProxy, Proxy: &config.Proxy{Target: "127.0.0.1:3001"},
			QuickShare: &config.QuickShare{Port: 8789, MetricsPort: 20243}},
	}
	c.Normalize()
	j, err := BuildCaddyJSON(c, Options{LogDir: `C:\logs`, QuickHosts: map[string]string{"blog": "a-b.trycloudflare.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string `json:"listen"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(j, &root); err != nil {
		t.Fatal(err)
	}
	srv := root.Apps.HTTP.Servers
	if len(srv) != 2 || srv["quick-blog"].Listen[0] != "127.0.0.1:8788" || srv[serverName].Listen[0] != "127.0.0.1:8787" {
		t.Fatalf("servers = %+v", srv)
	}
	if strings.Contains(string(j), "8789") {
		t.Error("a disabled site's quick share got a listener")
	}
	if _, err := BuildCaddyJSON(c, Options{LogDir: `C:\logs`, QuickHosts: map[string]string{"blog": "evil.example.com"}}); err == nil {
		t.Error("a hostname outside trycloudflare.com was accepted")
	}
}
