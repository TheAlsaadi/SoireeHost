package worker

// Regression test from the 12 Nov 2026 skills review (docs/reviews/2026-11-12-skills-review.md).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// trailerUpstream reports the headers and, after reading the body, the
// trailers it received.
func trailerUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"headers": r.Header, "trailers": r.Trailer})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStripsOtherForwardedSpellings(t *testing.T) {
	up := trailerUpstream(t)
	h := startHarness(t, func(c *config.Config) { c.Sites[1].Proxy.Target = up.Listener.Addr().String() })
	forged := []string{
		"Forwarded-For: 6.6.6.6", "X-Forwarded: for=6.6.6.6", "X-Forwarded-By: 6.6.6.6",
		"Proxy-Client-IP: 6.6.6.6", "WL-Proxy-Client-IP: 6.6.6.6", "X-Original-Forwarded-Host: evil.example",
		"X-Forwarded-Client-Ip: 6.6.6.6",
	}
	r := h.get(t, "app.example.com", "/", append(forged, "CF-Connecting-IP: 203.0.113.7")...)
	if r.status != 200 {
		t.Fatalf("status %d %q", r.status, r.body)
	}
	var got struct {
		Headers http.Header `json:"headers"`
	}
	if err := json.Unmarshal([]byte(r.body), &got); err != nil {
		t.Fatal(err)
	}
	for _, f := range forged {
		name, _, _ := strings.Cut(f, ":")
		if v := got.Headers.Values(name); len(v) != 0 {
			t.Errorf("R-11: forged %s reached the app: %q", name, v)
		}
	}
	if v := got.Headers.Get("X-Forwarded-For"); v != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q", v)
	}
}

func TestStripsForwardedTrailers(t *testing.T) {
	up := trailerUpstream(t)
	h := startHarness(t, func(c *config.Config) { c.Sites[1].Proxy.Target = up.Listener.Addr().String() })
	r := h.raw(t, "POST / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n"+
		"CF-Connecting-IP: 203.0.113.7\r\nTransfer-Encoding: chunked\r\nTrailer: X-Forwarded-For, X-Real-Ip\r\n\r\n"+
		"3\r\nabc\r\n0\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-Ip: 6.6.6.6\r\n\r\n")
	if r.status != 200 {
		t.Fatalf("status %d %q", r.status, r.body)
	}
	t.Logf("upstream saw: %s", r.body)
	var got struct {
		Headers  http.Header `json:"headers"`
		Trailers http.Header `json:"trailers"`
	}
	if err := json.Unmarshal([]byte(r.body), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.body, "6.6.6.6") {
		t.Errorf("R-11: forged forwarding value reached the app via trailers: headers=%v trailers=%v", got.Headers, got.Trailers)
	}
}
