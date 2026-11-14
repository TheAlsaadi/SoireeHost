// Package worker is the web worker: embedded Caddy serving the configured
// sites on loopback, with the SoiréeHost guard, rate limit, rooted file system
// and log filters compiled in as Caddy modules.
//
// Caddy keeps its running config in process-wide state, so a process runs at
// most one worker; Load replaces whatever was running.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
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

// ErrSelfCheck marks a failed listener self-check (S-01). The process must
// exit when it sees one (review finding R-05).
var ErrSelfCheck = errors.New("listener self-check (S-01)")

// LoadJSON runs a Caddy JSON config and then checks that this process listens
// on nothing but 127.0.0.1 and ::1 (S-01). If the check fails, Caddy is
// stopped and an error wrapping ErrSelfCheck is returned; the caller must
// exit.
func LoadJSON(j []byte) error {
	if err := checkAdminOff(j); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if err := caddy.Load(j, true); err != nil {
		return fmt.Errorf("starting web server: %w", err)
	}
	if err := CheckOwnListeners(); err != nil {
		stopErr := caddy.Stop()
		return errors.Join(fmt.Errorf("%w: %w", ErrSelfCheck, err), stopErr)
	}
	return nil
}

// WatchListeners repeats the listener self-check every interval until ctx
// ends. If a check fails it stops Caddy and returns an error wrapping
// ErrSelfCheck; the caller must exit (ADR-0005, S-01).
func WatchListeners(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := CheckOwnListeners(); err != nil {
				return errors.Join(fmt.Errorf("%w: %w", ErrSelfCheck, err), Stop())
			}
		}
	}
}

// checkAdminOff refuses a config that would start Caddy's admin API or save
// the config to disk (S-04, review finding SE-20). Caddy starts its
// unauthenticated admin endpoint on localhost:2019 for any config, including
// an empty or null one, unless admin.disabled is true, and the loopback
// self-check cannot tell that endpoint from a site. The decoding matches
// Caddy's own (encoding/json: case-insensitive names, the last duplicate
// wins), so the value checked is the value Caddy uses.
func checkAdminOff(j []byte) error {
	var c struct {
		Admin *struct {
			Disabled bool `json:"disabled"`
			Config   *struct {
				Persist *bool `json:"persist"`
			} `json:"config"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(j, &c); err != nil {
		return fmt.Errorf("web server config: %w", err)
	}
	if c.Admin == nil || !c.Admin.Disabled {
		return errors.New("web server config refused: the admin endpoint is not disabled (S-04)")
	}
	if c.Admin.Config == nil || c.Admin.Config.Persist == nil || *c.Admin.Config.Persist {
		return errors.New("web server config refused: config persistence is not turned off (S-04)")
	}
	// Caddy starts its remote admin endpoint whenever admin.remote is set,
	// even with admin.disabled, and admin.identity makes it fetch
	// certificates, so the admin and config objects may hold nothing else.
	// Every occurrence is checked: Go's decoder, which Caddy uses, matches
	// names case-insensitively and merges a repeated object into the same
	// struct, so a "remote" in an earlier duplicate would survive.
	admins, err := members(j, "admin")
	if err != nil {
		return fmt.Errorf("web server config: %w", err)
	}
	for _, a := range admins {
		if err := onlyKeys(a, "admin", "disabled", "config"); err != nil {
			return err
		}
		cfgs, err := members(a, "config")
		if err != nil {
			return fmt.Errorf("web server config: %w", err)
		}
		for _, c := range cfgs {
			if err := onlyKeys(c, "admin.config", "persist"); err != nil {
				return err
			}
		}
	}
	return nil
}

// members returns every value whose key matches name case-insensitively in
// the JSON object obj, duplicates included, in order. A value that is not an
// object has no members.
func members(obj []byte, name string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	err := eachMember(obj, func(k string, v json.RawMessage) {
		if strings.EqualFold(k, name) {
			out = append(out, v)
		}
	})
	return out, err
}

// onlyKeys refuses the JSON object obj if it has a key that does not match
// one of allowed case-insensitively.
func onlyKeys(obj []byte, where string, allowed ...string) error {
	var bad string
	err := eachMember(obj, func(k string, _ json.RawMessage) {
		if bad == "" && !slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, k) }) {
			bad = k
		}
	})
	if err != nil {
		return fmt.Errorf("web server config: %w", err)
	}
	if bad != "" {
		return fmt.Errorf("web server config refused: %s.%s is not allowed (S-04)", where, bad)
	}
	return nil
}

// eachMember calls fn for every key and value of the JSON object obj, in
// order and with duplicates. It does nothing if obj is not an object.
func eachMember(obj []byte, fn func(string, json.RawMessage)) error {
	dec := json.NewDecoder(bytes.NewReader(obj))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		fn(k, v)
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

// Endpoint is one socket this process has bound for receiving.
type Endpoint = winsec.Endpoint

// OwnEndpoints lists every listening TCP socket and bound UDP socket owned by
// this process.
func OwnEndpoints() ([]Endpoint, error) { return winsec.EndpointsOf(windows.GetCurrentProcessId()) }

func checkEndpoints(eps []Endpoint) error { return winsec.CheckLoopbackOnly(eps) }

// SelfCheckInterval is how often Run repeats the listener self-check.
const SelfCheckInterval = time.Minute

// Run loads cfg and serves until ctx is cancelled or a periodic self-check
// fails.
func Run(ctx context.Context, cfg config.Config, opts Options) error {
	if err := Load(cfg, opts); err != nil {
		return err
	}
	if err := WatchListeners(ctx, SelfCheckInterval); err != nil {
		return err
	}
	return Stop()
}
