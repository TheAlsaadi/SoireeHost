package setup

import (
	"strings"
	"testing"
)

// S-02: setup's only firewall rules block inbound traffic to its two
// programs; nothing it runs could add an allow rule or an outbound rule.
func TestFirewallCommandLines(t *testing.T) {
	l := Layout{ProgramDir: `C:\Program Files\SoireeHost`}
	rules := l.firewallRules()
	if len(rules) != 2 || rules[0][1] != `C:\Program Files\SoireeHost\soireehost.exe` || rules[1][1] != `C:\Program Files\SoireeHost\cloudflared.exe` {
		t.Fatalf("rules %v", rules)
	}
	for _, r := range rules {
		add := netshAdd(r[0], r[1])
		for _, want := range []string{"dir=in", "action=block", "enable=yes", "profile=any", `program="` + r[1] + `"`} {
			if !strings.Contains(add, want) {
				t.Errorf("%s lacks %s", add, want)
			}
		}
		if strings.Contains(add, "allow") || strings.Contains(add, "dir=out") {
			t.Errorf("%s could allow traffic", add)
		}
		if del := netshDelete(r[0]); !strings.HasPrefix(del, "advfirewall firewall delete rule name=") {
			t.Errorf("delete %s", del)
		}
	}
}
