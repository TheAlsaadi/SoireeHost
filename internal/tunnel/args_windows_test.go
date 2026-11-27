package tunnel

import (
	"slices"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// TestCloudflaredArgsCarryNoToken: the token reaches cloudflared only
// through TUNNEL_TOKEN, never its command line, which any local account can
// read (S-23); auto-update and remote diagnostics stay off, and metrics stay
// on loopback (S-04). The launcher test's fake cloudflared cannot show this,
// because the scrubber removes the token from every line it logs (Phase 7
// compliance review, 21 Nov 2026).
func TestCloudflaredArgsCarryNoToken(t *testing.T) {
	// built from pieces, so the secret scan does not take the fixture for a
	// real key (conventions rule 21)
	token := strings.Join([]string{"eyJhIjoi", "Q0FOQVJZ", "LUFSR1Mi", "fQ=="}, "")
	for _, s := range []spec{
		{kind: ipc.TunnelKindToken, token: token, metricsPort: 20241},
		{kind: ipc.TunnelKindQuick, siteID: "blog", token: token, port: 8788, metricsPort: 20301},
	} {
		args := cloudflaredArgs(s)
		line := strings.Join(args, " ")
		if strings.Contains(line, token) || strings.Contains(line, "--token") {
			t.Errorf("%s: the token is on the command line: %s", s.kind, line)
		}
		for _, want := range []string{"--no-autoupdate", "--management-diagnostics=false"} {
			if !slices.Contains(args, want) {
				t.Errorf("%s: %s missing: %s", s.kind, want, line)
			}
		}
		i := slices.Index(args, "--metrics")
		if i < 0 || i+1 >= len(args) || !strings.HasPrefix(args[i+1], "127.0.0.1:") {
			t.Errorf("%s: metrics not on loopback: %s", s.kind, line)
		}
		if s.kind == ipc.TunnelKindQuick && !slices.Contains(args, "http://127.0.0.1:8788") {
			t.Errorf("quick share does not point at its loopback port: %s", line)
		}
	}
	env := (&Launcher{}).env(spec{kind: ipc.TunnelKindToken, token: token})
	if !slices.Contains(env, "TUNNEL_TOKEN="+token) {
		t.Error("the token tunnel's environment has no TUNNEL_TOKEN")
	}
	if env := (&Launcher{}).env(spec{kind: ipc.TunnelKindQuick, token: token}); slices.ContainsFunc(env, func(e string) bool { return strings.Contains(e, token) }) {
		t.Error("a quick share's environment carries the token")
	}
}
