package waf

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"golang.org/x/sync/semaphore"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

func init() {
	caddy.RegisterModule(Firewall{})
}

// LoggerName is the name of the logger the handler writes firewall events
// to; the worker's Caddy config routes it to firewall.log.
const LoggerName = "http.handlers.soireehost_waf"

// BodyBudget caps the request bodies buffered for inspection at once, across
// every site, so a burst of uploads cannot push the worker past its 1 GiB job
// memory cap (S-21, ADR-0008).
const BodyBudget int64 = 192 << 20

var budget = semaphore.NewWeighted(BodyBudget)

// pool shares one WAF per mode and paranoia level across sites and config
// reloads.
var pool = caddy.NewUsagePool()

type pooledWAF struct{ waf coraza.WAF }

func (*pooledWAF) Destruct() error { return nil }

// Firewall is the soireehost_waf handler. It sits after the guard and the
// request body limit in every site route whose firewall is not Off.
type Firewall struct {
	// Site is the site id, written into each event.
	Site string `json:"site"`
	// Mode is "block" or "detect".
	Mode string `json:"mode"`
	// ParanoiaLevel is 1 to 4.
	ParanoiaLevel int `json:"paranoia_level"`

	waf     coraza.WAF
	poolKey string
	logger  eventLogger
}

// CaddyModule returns the Caddy module information.
func (Firewall) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.soireehost_waf",
		New: func() caddy.Module { return new(Firewall) },
	}
}

// Provision checks the settings and takes the shared WAF for them, building
// it on first use.
func (f *Firewall) Provision(ctx caddy.Context) error {
	if !config.ValidSiteID(f.Site) {
		return fmt.Errorf("soireehost_waf: bad site id %q", f.Site)
	}
	d, err := directives(f.Mode, f.ParanoiaLevel)
	if err != nil {
		return fmt.Errorf("soireehost_waf: %w", err)
	}
	f.logger = ctx.Logger(f)
	f.poolKey = "soireehost-waf-" + f.Mode + "-" + strconv.Itoa(f.ParanoiaLevel)
	v, _, err := pool.LoadOrNew(f.poolKey, func() (caddy.Destructor, error) {
		w, err := NewWAF(d)
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: w}, nil
	})
	if err != nil {
		return fmt.Errorf("soireehost_waf: building the firewall: %w", err)
	}
	pw, ok := v.(*pooledWAF)
	if !ok {
		return errors.New("soireehost_waf: unexpected pool entry")
	}
	f.waf = pw.waf
	return nil
}

// NewWAF builds a Coraza WAF from directives over the embedded rule set,
// with no debug log, no audit log and no error callback: events are built
// from the transaction afterwards, never from Coraza's own log text, which
// carries matched request data (S-18).
func NewWAF(directives string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(rulesFS()).
		WithDebugLogger(debuglog.Noop()).
		WithDirectives(directives))
}

// Cleanup releases the shared WAF.
func (f *Firewall) Cleanup() error {
	_, err := pool.Delete(f.poolKey)
	return err
}

var (
	_ caddy.Provisioner  = (*Firewall)(nil)
	_ caddy.CleanerUpper = (*Firewall)(nil)
)
