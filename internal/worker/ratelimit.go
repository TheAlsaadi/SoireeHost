package worker

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(RateLimit{})
}

// DefaultMaxClients bounds how many client addresses one site tracks at once.
// Each entry is a few dozen bytes. When the table is full of clients that are
// all still inside their window, new clients are refused (fail closed).
const DefaultMaxClients = 100_000

// RateLimit allows each client address at most PerMinute requests a minute
// (S-15), using the generic cell rate algorithm: a burst of up to PerMinute
// requests, then one request every 60s/PerMinute. IPv6 clients are grouped by
// /64, because one host can use a whole /64.
//
// The design choice (in-house rather than mholt/caddy-ratelimit) is recorded
// in docs/adr/0005-web-worker.md.
type RateLimit struct {
	PerMinute  int `json:"per_minute"`
	MaxClients int `json:"max_clients,omitempty"`

	limiter *limiter
}

// CaddyModule returns the Caddy module information.
func (RateLimit) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.soireehost_ratelimit",
		New: func() caddy.Module { return new(RateLimit) },
	}
}

// Provision builds the limiter.
func (rl *RateLimit) Provision(caddy.Context) error {
	if rl.PerMinute < 1 {
		return errors.New("soireehost_ratelimit: per_minute must be at least 1")
	}
	if rl.MaxClients == 0 {
		rl.MaxClients = DefaultMaxClients
	}
	rl.limiter = newLimiter(rl.PerMinute, time.Minute, rl.MaxClients, time.Now)
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (rl RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	ok, retry := rl.limiter.allow(clientKey(ip))
	if !ok {
		secs := int(retry / time.Second)
		if retry%time.Second != 0 {
			secs++
		}
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		return caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("rate limit of %d requests a minute exceeded", rl.PerMinute))
	}
	return next.ServeHTTP(w, r)
}

// clientKey returns the address a client is counted under: the IPv4 address,
// or the /64 of an IPv6 address. Unparseable input shares one bucket.
func clientKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "invalid"
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// limiter implements GCRA. For each key it keeps the theoretical arrival time
// (tat) of the next request. A request at time now is allowed when
// tat - now <= burst, and then moves tat forward by one interval.
type limiter struct {
	mu        sync.Mutex
	interval  time.Duration // time per request
	burst     time.Duration // (n-1) * interval: how far tat may run ahead of now
	max       int
	now       func() time.Time
	tat       map[string]time.Time
	lastSweep time.Time
}

func newLimiter(n int, per time.Duration, maxKeys int, now func() time.Time) *limiter {
	interval := per / time.Duration(n)
	return &limiter{
		interval:  interval,
		burst:     time.Duration(n-1) * interval,
		max:       maxKeys,
		now:       now,
		tat:       make(map[string]time.Time),
		lastSweep: now(),
	}
}

// allow reports whether a request for key may proceed, and if not, how long
// until it would.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.interval+l.burst {
		l.sweep(now)
	}
	tat, seen := l.tat[key]
	if !seen {
		if len(l.tat) >= l.max {
			l.sweep(now)
			if len(l.tat) >= l.max {
				return false, l.interval
			}
		}
		tat = now
	}
	if tat.Before(now) {
		tat = now
	}
	if ahead := tat.Sub(now); ahead > l.burst {
		return false, ahead - l.burst
	}
	l.tat[key] = tat.Add(l.interval)
	return true, 0
}

// sweep forgets keys whose window has fully passed.
func (l *limiter) sweep(now time.Time) {
	for k, t := range l.tat {
		if !t.After(now) {
			delete(l.tat, k)
		}
	}
	l.lastSweep = now
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tat)
}

var (
	_ caddy.Provisioner           = (*RateLimit)(nil)
	_ caddyhttp.MiddlewareHandler = (*RateLimit)(nil)
)
