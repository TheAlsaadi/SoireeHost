package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/accesslog"
	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

// Control API methods (ADR-0006). No method takes a command to run, and the
// only path any method accepts is a site folder to publish, which the
// supervisor resolves and checks but never writes (S-31).
const (
	MethodStatus         = "status.get"
	MethodConfigGet      = "config.get"
	MethodConfigHistory  = "config.history"
	MethodConfigRollback = "config.rollback"
	MethodSitePut        = "site.put"
	MethodSiteRemove     = "site.remove"
	MethodSiteSetEnabled = "site.set_enabled"
	MethodSecretSet      = "secret.set"
	MethodSecretStatus   = "secret.status"
	MethodAuditList      = "audit.list"
	// Phase 3 (ADR-0007)
	MethodQuickShareStart = "quickshare.start"
	MethodQuickShareStop  = "quickshare.stop"
	MethodTunnelOffline   = "tunnel.set_offline"
	// Phase 4 (ADR-0008)
	MethodFirewallEvents = "firewall.events"
	// Phase 5 (ADR-0009)
	MethodAccessList   = "access.list"
	MethodConfigExport = "config.export"
	MethodConfigImport = "config.import"
)

// Request is one control call.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response answers one Request: exactly one of Result and Error is set.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error codes, a closed set the control panel can act on.
const (
	CodeInvalid              = "invalid"
	CodeNotFound             = "not_found"
	CodeConfirmationRequired = "confirmation_required"
	CodeForbidden            = "forbidden"
	CodeUnavailable          = "unavailable"
	CodeInternal             = "internal"
)

// Error is a failed call. Message is a plain sentence the control panel shows
// as text (S-34); it never contains a secret. A confirmation_required error
// carries the Confirmation to send back if the user agrees (S-32, SE-27).
type Error struct {
	Code         string        `json:"code"`
	Message      string        `json:"message"`
	Confirmation *Confirmation `json:"confirmation,omitempty"`
	// WorkerDetail is a worker's own account of a failure, cleaned to one
	// short line (DR-6). The control panel shows it apart from Message,
	// labelled as coming from the web server, never as SoiréeHost's words.
	WorkerDetail string `json:"worker_detail,omitempty"`
}

// Confirmation is the supervisor's offer to accept one weakening change
// (S-32, review finding SE-27). Sentences say exactly what the change
// weakens; the control panel shows them, as text, and if the user confirms
// sends the same call again with Token in its confirmation field. The token
// is single-use, bound to the caller, the method, the call's parameters and
// these sentences, and expires at Expires.
type Confirmation struct {
	Token     string    `json:"token"`
	Sentences []string  `json:"sentences"`
	Expires   time.Time `json:"expires"`
}

// ConfirmationTTL is how long a confirmation token stays valid.
const ConfirmationTTL = 2 * time.Minute

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an *Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Parameters and results.

// None is the empty params or result.
type None struct{}

// StatusResult is the answer to status.get.
type StatusResult struct {
	Version    string         `json:"version"`
	State      string         `json:"state"`
	Revision   uint64         `json:"revision"`
	Workers    []WorkerStatus `json:"workers"`
	Warnings   []string       `json:"warnings,omitempty"`
	AuditOK    bool           `json:"audit_ok"`
	StartedAt  time.Time      `json:"started_at"`
	ConfigNote string         `json:"config_note,omitempty"`
	Tunnel     TunnelStatus   `json:"tunnel"`
}

// TunnelStatus is the state of the tunnels as status.get reports it. It never
// holds a secret.
type TunnelStatus struct {
	// Offline is the offline switch.
	Offline bool `json:"offline"`
	// TokenSet says whether a tunnel token is stored.
	TokenSet bool `json:"token_set"`
	// ServiceURL is what to enter as the service of every public hostname
	// in the Cloudflare dashboard (tunnel-token mode).
	ServiceURL string `json:"service_url"`
	// RepairNeeded is set when cloudflared.exe is missing or changed; the
	// control panel then offers Repair (S-23).
	RepairNeeded bool `json:"repair_needed"`
	// Tunnels lists each tunnel the launcher runs or should run.
	Tunnels []TunnelView `json:"tunnels"`
	// Warnings are plain sentences about the tunnels.
	Warnings []string `json:"warnings,omitempty"`
}

// TunnelView is one tunnel as the control panel shows it.
type TunnelView struct {
	Kind        string `json:"kind"`
	SiteID      string `json:"site_id,omitempty"`
	State       string `json:"state"`
	Connections int    `json:"connections"`
	// URL is a quick share's link, once cloudflared has been given one.
	URL string `json:"url,omitempty"`
	// Temporary marks a quick share link, and Label says what that means
	// (S-51).
	Temporary bool      `json:"temporary"`
	Label     string    `json:"label,omitempty"`
	Since     time.Time `json:"since,omitzero"`
}

// QuickShareLabel is shown beside every quick share link (S-51).
const QuickShareLabel = "Temporary link for testing. It changes whenever the tunnel restarts."

// QuickShareParams names the site to share or stop sharing.
type QuickShareParams struct {
	SiteID string `json:"site_id"`
}

// OfflineParams sets the offline switch.
type OfflineParams struct {
	Offline bool `json:"offline"`
}

// WorkerStatus is one worker's state as the supervisor sees it.
type WorkerStatus struct {
	Role      string    `json:"role"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`
	// LastErrorDetail is the worker's own cleaned detail for LastError, if
	// it gave one (DR-6).
	LastErrorDetail string `json:"last_error_detail,omitempty"`
	Restarts        int    `json:"restarts"`
}

// ConfigResult is the answer to config.get and the changing calls.
type ConfigResult struct {
	Revision uint64        `json:"revision"`
	Config   config.Config `json:"config"`
	Warnings []string      `json:"warnings,omitempty"`
	// Exposure is the exposure check of the folder a site.put or
	// site.set_enabled just put live, if it ran (ADR-0008).
	Exposure *sitecheck.ExposureReport `json:"exposure,omitempty"`
}

// HistoryResult is the answer to config.history.
type HistoryResult struct {
	Revisions []config.Record `json:"revisions"`
	LastGood  uint64          `json:"last_good"`
}

// RollbackParams selects a revision to restore. Going back to settings that
// weaken protection (a new LAN target, a weaker firewall) needs a
// confirmation token (S-32).
type RollbackParams struct {
	Revision     uint64 `json:"revision"`
	Confirmation string `json:"confirmation,omitempty"`
}

// SitePutParams adds or replaces a site. A change that weakens protection
// needs a confirmation token (S-32).
type SitePutParams struct {
	Site         config.Site `json:"site"`
	Confirmation string      `json:"confirmation,omitempty"`
}

// SiteIDParams names a site.
type SiteIDParams struct {
	ID string `json:"id"`
}

// SiteEnabledParams turns a site on or off. Putting a static folder live
// when the exposure check finds a file that would be served and looks like
// a secret needs a confirmation token (S-32, ADR-0008).
type SiteEnabledParams struct {
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Confirmation string `json:"confirmation,omitempty"`
}

// FirewallEventsParams pages through the firewall events: one site's (all
// sites' if empty), older than Before (newest if zero), at most Limit
// (1 to MaxFirewallPage; zero means 100).
type FirewallEventsParams struct {
	SiteID string    `json:"site_id"`
	Before time.Time `json:"before,omitzero"`
	Limit  int       `json:"limit"`
}

// MaxFirewallPage bounds one firewall.events answer.
const MaxFirewallPage = fwevent.MaxPage

// FirewallEventsResult is one page of firewall events, newest first. Every
// field of an event is attacker-influenced text for display only (S-34).
// Skipped counts log lines that were not valid events; More says older
// events may exist.
type FirewallEventsResult struct {
	Events  []fwevent.Event `json:"events"`
	Skipped int             `json:"skipped"`
	More    bool            `json:"more"`
}

// SecretSetParams sets a secret. The value is write-only (S-35). Replacing a
// secret that is set needs a confirmation token (S-32).
type SecretSetParams struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	Confirmation string `json:"confirmation,omitempty"`
}

// SecretStatusResult lists which secrets are set and when, never their values.
type SecretStatusResult struct {
	Secrets  []SecretStatus `json:"secrets"`
	Warnings []string       `json:"warnings,omitempty"`
}

// SecretStatus is one secret's state.
type SecretStatus struct {
	Name  string    `json:"name"`
	Set   bool      `json:"set"`
	SetAt time.Time `json:"set_at,omitzero"`
}

// AccessListParams pages through the web server's access log, newest first:
// one site's requests (all sites' if empty), of one result class (all if
// empty), newer than After and older than Before (no bound if zero), at most
// Limit (1 to MaxAccessPage; zero means accesslog.DefaultPage).
type AccessListParams struct {
	SiteID string    `json:"site_id"`
	Class  string    `json:"class"`
	After  time.Time `json:"after,omitzero"`
	Before time.Time `json:"before,omitzero"`
	Limit  int       `json:"limit"`
}

// MaxAccessPage bounds one access.list answer.
const MaxAccessPage = accesslog.MaxPage

// AccessListResult is one page of requests, newest first. Every field of an
// entry is attacker-influenced text for display only (S-34). Skipped counts
// log lines that were not valid entries; More says older entries may exist.
type AccessListResult struct {
	Entries []AccessEntry `json:"entries"`
	Skipped int           `json:"skipped"`
	More    bool          `json:"more"`
}

// AccessEntry is one request with the site it was for (empty if the host
// matched no site) and, for a request the firewall blocked or would have
// blocked, the rules that matched.
type AccessEntry struct {
	accesslog.Entry
	SiteID   string         `json:"site_id,omitempty"`
	Firewall *FirewallMatch `json:"firewall,omitempty"`
}

// FirewallMatch is the firewall's verdict on one request: blocked, or
// detected in Detect only, and the rules that matched.
type FirewallMatch struct {
	Action string         `json:"action"`
	Rules  []fwevent.Rule `json:"rules"`
}

// ConfigImportParams replaces the settings with an imported copy. It always
// needs a confirmation token, which names what the import changes (S-32).
type ConfigImportParams struct {
	Config       config.Config `json:"config"`
	Confirmation string        `json:"confirmation,omitempty"`
}

// ConfigExportResult is the settings to save to a file. It never holds a
// secret (S-40).
type ConfigExportResult struct {
	Revision uint64        `json:"revision"`
	Config   config.Config `json:"config"`
}

// AuditListParams pages through the audit log.
type AuditListParams struct {
	After uint64 `json:"after"`
	Limit int    `json:"limit"`
}

// MaxAuditPage bounds one audit.list answer.
const MaxAuditPage = 500

// AuditListResult is one page of the audit log with the chain check result.
type AuditListResult struct {
	Entries []audit.Entry `json:"entries"`
	Report  audit.Report  `json:"report"`
}

// paramTypes maps each method to a constructor for its params.
var paramTypes = map[string]func() any{
	MethodStatus:          func() any { return &None{} },
	MethodConfigGet:       func() any { return &None{} },
	MethodConfigHistory:   func() any { return &None{} },
	MethodConfigRollback:  func() any { return &RollbackParams{} },
	MethodSitePut:         func() any { return &SitePutParams{} },
	MethodSiteRemove:      func() any { return &SiteIDParams{} },
	MethodSiteSetEnabled:  func() any { return &SiteEnabledParams{} },
	MethodSecretSet:       func() any { return &SecretSetParams{} },
	MethodSecretStatus:    func() any { return &None{} },
	MethodAuditList:       func() any { return &AuditListParams{} },
	MethodQuickShareStart: func() any { return &QuickShareParams{} },
	MethodQuickShareStop:  func() any { return &QuickShareParams{} },
	MethodTunnelOffline:   func() any { return &OfflineParams{} },
	MethodFirewallEvents:  func() any { return &FirewallEventsParams{} },
	MethodAccessList:      func() any { return &AccessListParams{} },
	MethodConfigExport:    func() any { return &None{} },
	MethodConfigImport:    func() any { return &ConfigImportParams{} },
}

// Methods lists every control method.
func Methods() []string {
	out := make([]string, 0, len(paramTypes))
	for m := range paramTypes {
		out = append(out, m)
	}
	return out
}

// DecodeRequest parses a control request strictly and decodes its params
// into the method's own type. An unknown method, unknown field, missing
// params where some are required, or trailing data is an error.
func DecodeRequest(data []byte) (Request, any, error) {
	var req Request
	if err := decodeStrict(data, &req); err != nil {
		return Request{}, nil, fmt.Errorf("malformed request: %w", err)
	}
	mk, ok := paramTypes[req.Method]
	if !ok {
		return req, nil, fmt.Errorf("unknown method %q", req.Method)
	}
	params := mk()
	raw := req.Params
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	if err := decodeStrict(raw, params); err != nil {
		return req, nil, fmt.Errorf("malformed params for %s: %w", req.Method, err)
	}
	return req, params, nil
}

// DecodeResponse parses a response strictly.
func DecodeResponse(data []byte) (Response, error) {
	var resp Response
	if err := decodeStrict(data, &resp); err != nil {
		return Response{}, fmt.Errorf("malformed response: %w", err)
	}
	if (resp.Error == nil) == (len(resp.Result) == 0) {
		return Response{}, errors.New("malformed response: needs exactly one of result and error")
	}
	return resp, nil
}

// String hides the secret value, so a SecretSetParams printed by mistake
// never shows it.
func (p SecretSetParams) String() string {
	return fmt.Sprintf("secret.set(name=%s confirmed=%v value=REDACTED)", p.Name, p.Confirmation != "")
}

// GoString hides the value from %#v as well.
func (p SecretSetParams) GoString() string { return p.String() }
