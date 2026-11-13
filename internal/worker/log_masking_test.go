package worker

// Regression tests for R-19 (raw '#' in the request target) and SE-32
// (credentials under names a deny-list misses), both S-18: every query value
// is masked, including after a raw '#'.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// fpLoggedMarker marks values these PoCs expect to find in the shared access
// log. It is deliberately not secretMarker, so TestLogRedaction (which scans
// the same log file later in the run) is not failed by these PoCs.
const fpLoggedMarker = "FPCHECK-LOGGED"

func TestRedactURIRawHash(t *testing.T) {
	in := "/p?a=1#&token=SECRETVALUE"
	got := RedactURI(in)
	t.Logf("RedactURI(%q) = %q", in, got)
	if strings.Contains(got, "SECRETVALUE") {
		t.Errorf("R-19: RedactURI left the token after a raw '#' unmasked: %q", got)
	}
}

// queryUpstream reports how the app parsed the query.
func queryUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"raw_query": r.URL.RawQuery, "token": r.URL.Query().Get("token")})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func accessLogLines(t *testing.T, h *harness, marker string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.logDir, AccessLogName))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, marker) {
			out = append(out, l)
		}
	}
	return out
}

func TestLogMasksAfterRawHash(t *testing.T) {
	up := queryUpstream(t)
	h := startHarness(t, func(c *config.Config) { c.Sites[1].Proxy.Target = up.Listener.Addr().String() })
	marker := fpLoggedMarker + "-R19"
	r := h.raw(t, "GET /p?a=1#&token="+marker+" HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\nCF-Connecting-IP: 203.0.113.7\r\n\r\n")
	t.Logf("worker -> %d, app saw %s", r.status, strings.TrimSpace(r.body))
	if r.status == 400 {
		return // refused: nothing reaches the app or the log
	}
	if lines := accessLogLines(t, h, marker); len(lines) > 0 {
		t.Errorf("R-19: secret logged unmasked:\n%s", strings.Join(lines, "\n"))
	}
}

func TestRedactURIMasksEveryName(t *testing.T) {
	for _, p := range []string{"code", "sig", "jwt", "otp", "ticket", "SAMLResponse", "assertion"} {
		in := "/cb?" + p + "=SECRETVALUE"
		if got := RedactURI(in); strings.Contains(got, "SECRETVALUE") {
			t.Errorf("SE-32: %s value logged in clear: %q", p, got)
		}
	}
	// negative: names containing a deny-list word are masked today
	for _, p := range []string{"id_token_hint", "X-Amz-Signature", "access_token"} {
		if got := RedactURI("/cb?" + p + "=SECRETVALUE"); strings.Contains(got, "SECRETVALUE") {
			t.Errorf("deny-list name %s not masked: %q", p, got)
		}
	}
}

func TestLogMasksCredentialParams(t *testing.T) {
	h := startHarness(t, nil)
	marker := fpLoggedMarker + "-SE32"
	h.get(t, "app.example.com", "/oauth/callback?code="+marker+"-CODE&state=x", "CF-Connecting-IP: 203.0.113.7")
	h.get(t, "blog.example.com", "/download?sig="+marker+"-SIG&exp=1", "CF-Connecting-IP: 203.0.113.7",
		"Referer: https://idp.example/sso?SAMLResponse="+marker+"-SAML")
	if lines := accessLogLines(t, h, marker); len(lines) > 0 {
		t.Errorf("SE-32: %d access-log line(s) carry secret query values:\n%s", len(lines), strings.Join(lines, "\n"))
	}
}
