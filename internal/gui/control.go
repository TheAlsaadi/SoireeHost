package gui

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
)

// callTimeout bounds one control call from the UI. The supervisor's own
// work (a folder check, a worker load) is bounded well inside it.
const callTimeout = 90 * time.Second

// caller is the part of ipc.Client the bindings use, so tests can stand in
// for the supervisor.
type caller interface {
	Call(ctx context.Context, method string, params, out any) error
}

// Control is bound to the UI: one method per control call it needs. It holds
// no secret and validates nothing itself; the supervisor's answer is the
// truth (S-31). Errors from the supervisor reach the UI as *ipc.Error, with
// any confirmation offer and worker detail in them (marshalError).
type Control struct {
	c caller

	mu      sync.Mutex
	pending *config.Config // an imported file waiting for confirmation
}

// NewControl returns the service over a control client.
func NewControl(c caller) *Control { return &Control{c: c} }

func call[T any](ctx context.Context, c caller, method string, params any) (T, error) {
	var out T
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	err := c.Call(ctx, method, params, &out)
	return out, err
}

// Status is the supervisor's state, for the status line and the tray.
func (s *Control) Status(ctx context.Context) (ipc.StatusResult, error) {
	return call[ipc.StatusResult](ctx, s.c, ipc.MethodStatus, ipc.None{})
}

// Config is the current settings. They never hold a secret (S-40).
func (s *Control) Config(ctx context.Context) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodConfigGet, ipc.None{})
}

// PutSite adds or replaces a site. confirmation is empty on the first try;
// a weakening change answers confirmation_required with a token, which the
// UI sends back here only after the user has confirmed (S-32).
func (s *Control) PutSite(ctx context.Context, site config.Site, confirmation string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirmation: confirmation})
}

// SetSiteEnabled turns a site on or off.
func (s *Control) SetSiteEnabled(ctx context.Context, id string, enabled bool, confirmation string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodSiteSetEnabled, ipc.SiteEnabledParams{ID: id, Enabled: enabled, Confirmation: confirmation})
}

// RemoveSite removes a site.
func (s *Control) RemoveSite(ctx context.Context, id string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodSiteRemove, ipc.SiteIDParams{ID: id})
}

// CheckForUpdates is "Check now": the supervisor checks in the background,
// and status.get follows it (ADR-0004).
func (s *Control) CheckForUpdates(ctx context.Context) (ipc.UpdateStatus, error) {
	return call[ipc.UpdateStatus](ctx, s.c, ipc.MethodUpdateCheck, ipc.None{})
}

// SetUpdateCheck turns the daily update check on or off. Off is a weakening
// change and needs the supervisor's confirmation token (S-32).
func (s *Control) SetUpdateCheck(ctx context.Context, check bool, confirmation string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodUpdateSetCheck, ipc.UpdateSetCheckParams{Check: check, Confirmation: confirmation})
}

// StartQuickShare shares a site through a temporary link (S-51).
func (s *Control) StartQuickShare(ctx context.Context, id string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodQuickShareStart, ipc.QuickShareParams{SiteID: id})
}

// StopQuickShare stops sharing a site.
func (s *Control) StopQuickShare(ctx context.Context, id string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodQuickShareStop, ipc.QuickShareParams{SiteID: id})
}

// SetOffline is the switch that takes everything off the internet.
func (s *Control) SetOffline(ctx context.Context, offline bool) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodTunnelOffline, ipc.OfflineParams{Offline: offline})
}

// Activity pages through the access log. Every field of every entry is
// attacker-controlled text; the UI shows it as text only (S-34).
func (s *Control) Activity(ctx context.Context, p ipc.AccessListParams) (ipc.AccessListResult, error) {
	return call[ipc.AccessListResult](ctx, s.c, ipc.MethodAccessList, p)
}

// FirewallEvents pages through the firewall log (S-34 applies as above).
func (s *Control) FirewallEvents(ctx context.Context, p ipc.FirewallEventsParams) (ipc.FirewallEventsResult, error) {
	return call[ipc.FirewallEventsResult](ctx, s.c, ipc.MethodFirewallEvents, p)
}

// AuditList pages through the audit log with its chain check.
func (s *Control) AuditList(ctx context.Context, p ipc.AuditListParams) (ipc.AuditListResult, error) {
	return call[ipc.AuditListResult](ctx, s.c, ipc.MethodAuditList, p)
}

// History lists the saved revisions of the settings.
func (s *Control) History(ctx context.Context) (ipc.HistoryResult, error) {
	return call[ipc.HistoryResult](ctx, s.c, ipc.MethodConfigHistory, ipc.None{})
}

// Rollback restores a saved revision.
func (s *Control) Rollback(ctx context.Context, revision uint64, confirmation string) (ipc.ConfigResult, error) {
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodConfigRollback, ipc.RollbackParams{Revision: revision, Confirmation: confirmation})
}

// SecretStatus says whether the tunnel token is set and when, never its
// value (S-35).
func (s *Control) SecretStatus(ctx context.Context) (ipc.SecretStatusResult, error) {
	return call[ipc.SecretStatusResult](ctx, s.c, ipc.MethodSecretStatus, ipc.None{})
}

// SetTunnelToken passes a tunnel token to the supervisor and keeps no copy.
// It is write-only: nothing in the control panel can read a token back
// (S-35).
func (s *Control) SetTunnelToken(ctx context.Context, value, confirmation string) (ipc.SecretStatusResult, error) {
	return call[ipc.SecretStatusResult](ctx, s.c, ipc.MethodSecretSet, ipc.SecretSetParams{Name: tunnelTokenName, Value: value, Confirmation: confirmation})
}

// tunnelTokenName is the one secret the control panel can set.
const tunnelTokenName = "tunnel_token"

// ExportConfig returns the settings as indented JSON for the UI to offer as
// a file. They never hold a secret (S-40).
func (s *Control) ExportConfig(ctx context.Context) (string, error) {
	res, err := call[ipc.ConfigExportResult](ctx, s.c, ipc.MethodConfigExport, ipc.None{})
	if err != nil {
		return "", err
	}
	b, err := res.Config.Encode()
	return string(b), err
}

// errNoImport is returned when a confirmation arrives with no import waiting.
var errNoImport = &ipc.Error{Code: ipc.CodeInvalid, Message: "There is no import waiting. Choose the file again."}

// ImportConfig reads settings exported earlier and asks the supervisor to
// import them. The first answer is always confirmation_required (S-32); the
// parsed settings wait here until ConfirmImport sends them again with the
// token, so the user confirms exactly what was read.
func (s *Control) ImportConfig(ctx context.Context, text string) (ipc.ConfigResult, error) {
	cfg, err := parseImport(text)
	if err != nil {
		return ipc.ConfigResult{}, err
	}
	s.mu.Lock()
	s.pending = &cfg
	s.mu.Unlock()
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodConfigImport, ipc.ConfigImportParams{Config: cfg})
}

// ConfirmImport sends the waiting import again with the user's confirmation.
func (s *Control) ConfirmImport(ctx context.Context, confirmation string) (ipc.ConfigResult, error) {
	s.mu.Lock()
	cfg := s.pending
	s.pending = nil
	s.mu.Unlock()
	if cfg == nil {
		return ipc.ConfigResult{}, errNoImport
	}
	return call[ipc.ConfigResult](ctx, s.c, ipc.MethodConfigImport, ipc.ConfigImportParams{Config: *cfg, Confirmation: confirmation})
}

// parseImport decodes an exported settings file strictly. Validation is the
// supervisor's; this only turns text into the typed shape.
func parseImport(text string) (config.Config, error) {
	if len(text) > config.MaxConfigBytes {
		return config.Config{}, &ipc.Error{Code: ipc.CodeInvalid, Message: "That file is too large to be SoiréeHost settings."}
	}
	var cfg config.Config
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return config.Config{}, &ipc.Error{Code: ipc.CodeInvalid, Message: "That file is not SoiréeHost settings. Choose a file made with Export settings."}
	}
	return cfg, nil
}

// marshalError gives the UI the supervisor's error as it is (code, message,
// confirmation offer, worker detail); any other failure becomes an
// "unavailable" error with a plain sentence. It never fails.
func marshalError(err error) []byte {
	var ie *ipc.Error
	if !errors.As(err, &ie) {
		msg := "SoiréeHost's service is not answering. Check that it is installed and running, then try again."
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "SoiréeHost's service took too long to answer. Try again."
		}
		ie = &ipc.Error{Code: ipc.CodeUnavailable, Message: msg}
	}
	b, jerr := json.Marshal(ie)
	if jerr != nil {
		return []byte(`{"code":"internal","message":"Something went wrong."}`)
	}
	return b
}
