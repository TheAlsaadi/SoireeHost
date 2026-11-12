// Package worker is the web worker: embedded Caddy serving the configured
// sites on loopback, with the SoiréeHost guard, rate limit, rooted file system
// and log filters compiled in as Caddy modules.
//
// Caddy keeps its running config in process-wide state, so a process runs at
// most one worker; Load replaces whatever was running.
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	// Caddy modules the generated config uses. Only these are compiled in.
	_ "github.com/caddyserver/caddy/v2/modules/caddyfs"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/requestbody"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"
	_ "github.com/caddyserver/caddy/v2/modules/logging"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

var mu sync.Mutex

// Load builds the Caddy config for cfg and runs it, replacing any running
// config, then runs the listener self-check.
func Load(cfg config.Config, opts Options) error {
	j, err := BuildCaddyJSON(cfg, opts)
	if err != nil {
		return err
	}
	return LoadJSON(j)
}

// LoadJSON runs a Caddy JSON config and then checks that this process listens
// on nothing but 127.0.0.1 and ::1 (S-01). If the check fails, Caddy is
// stopped and an error is returned; the caller must exit.
func LoadJSON(j []byte) error {
	mu.Lock()
	defer mu.Unlock()
	if err := caddy.Load(j, true); err != nil {
		return fmt.Errorf("starting web server: %w", err)
	}
	if err := CheckOwnListeners(); err != nil {
		stopErr := caddy.Stop()
		return errors.Join(fmt.Errorf("listener self-check (S-01): %w", err), stopErr)
	}
	return nil
}

// Stop stops the running config.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	return caddy.Stop()
}

// CheckOwnListeners fails if this process has a listening TCP socket or a
// bound UDP socket on any address other than 127.0.0.1 or ::1, or if the
// sockets cannot be listed (fail closed).
func CheckOwnListeners() error {
	eps, err := OwnEndpoints()
	if err != nil {
		return err
	}
	return checkEndpoints(eps)
}

func checkEndpoints(eps []Endpoint) error {
	var bad []error
	for _, ep := range eps {
		if !config.IsStrictLoopback(ep.Addr.Addr()) {
			bad = append(bad, fmt.Errorf("%s socket on %s is not loopback", ep.Proto, ep.Addr))
		}
	}
	return errors.Join(bad...)
}

// SelfCheckInterval is how often Run repeats the listener self-check.
const SelfCheckInterval = time.Minute

// Run loads cfg and serves until ctx is cancelled or a periodic self-check
// fails.
func Run(ctx context.Context, cfg config.Config, opts Options) error {
	if err := Load(cfg, opts); err != nil {
		return err
	}
	t := time.NewTicker(SelfCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return Stop()
		case <-t.C:
			if err := CheckOwnListeners(); err != nil {
				return errors.Join(fmt.Errorf("listener self-check (S-01): %w", err), Stop())
			}
		}
	}
}
