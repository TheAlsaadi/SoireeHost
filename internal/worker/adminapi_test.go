package worker

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// SE-20 (docs/reviews/2026-11-12-skills-review.md): Caddy starts its
// unauthenticated admin API on localhost:2019 for any config that does not
// disable it, including an empty one. LoadJSON refuses such a config before
// Caddy sees it, so the endpoint never starts.
func TestLoadJSONRefusesAdminAPI(t *testing.T) {
	adminUp := func() bool {
		c, err := dial(t, "127.0.0.1:2019", 500*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	if adminUp() {
		t.Skip("something already listens on 127.0.0.1:2019")
	}
	for _, j := range []string{
		``,
		`null`,
		`{}`,
		`{"apps":{}}`,
		`{"admin":{}}`,
		`{"admin":{"disabled":false,"config":{"persist":false}}}`,
		`{"admin":{"disabled":true}}`,
		`{"admin":{"disabled":true,"config":{}}}`,
		`{"admin":{"disabled":true,"config":{"persist":true}}}`,
		`{"admin":{"disabled":true,"config":{"persist":false}},"admin":{"disabled":false}}`,
		`{"ADMIN":{"DISABLED":false},"admin":{"disabled":true,"config":{"persist":false}},"Admin":{"Disabled":false}}`,
		// Caddy starts the remote admin endpoint even with disabled set
		`{"admin":{"disabled":true,"config":{"persist":false},"remote":{"listen":"127.0.0.1:2021"}}}`,
		`{"admin":{"disabled":true,"config":{"persist":false},"identity":{}}}`,
		`{"admin":{"disabled":true,"config":{"persist":false},"listen":"127.0.0.1:2019"}}`,
		`{"admin":{"disabled":true,"config":{"persist":false,"load":{}}}}`,
		// a repeated object is merged by the decoder, so remote survives
		`{"admin":{"remote":{"listen":"127.0.0.1:2021"}},"admin":{"disabled":true,"config":{"persist":false}}}`,
		`{"Admin":{"Remote":{"listen":"127.0.0.1:2021"}},"admin":{"disabled":true,"config":{"persist":false}}}`,
	} {
		err := LoadJSON([]byte(j))
		if err == nil {
			_ = Stop()
			t.Errorf("%q was loaded", j)
			continue
		}
		if j != `` && j != `null` && !strings.Contains(err.Error(), "S-04") {
			t.Errorf("%q: error does not name S-04: %v", j, err)
		}
		if adminUp() {
			t.Fatalf("%q started the admin API", j)
		}
	}
}

// The config the worker builds itself passes the check.
func TestCheckAdminOffAcceptsBuiltConfig(t *testing.T) {
	c := config.Default()
	c.Normalize()
	j, err := BuildCaddyJSON(c, Options{LogDir: `C:\logs`})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAdminOff(j); err != nil {
		t.Fatal(err)
	}
}

// R-05: the repeated self-check stops the worker when the process gains a
// socket beyond loopback after its config loaded. Binding a non-loopback
// address makes Windows Firewall prompt on a desktop, so this runs in CI.
func TestWatchListenersStopsOnPublicSocket(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("binds a non-loopback address, which makes Windows Firewall prompt on a desktop; runs in CI")
	}
	l, err := listen(t, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := WatchListeners(ctx, 50*time.Millisecond); !errors.Is(err, ErrSelfCheck) {
		t.Fatalf("watch ended with %v", err)
	}
}

// WatchListeners ends quietly when its context ends.
func TestWatchListenersEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := WatchListeners(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
}
