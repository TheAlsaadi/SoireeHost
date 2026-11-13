package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
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
// as text (S-34); it never contains a secret.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

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
}

// WorkerStatus is one worker's state as the supervisor sees it.
type WorkerStatus struct {
	Role      string    `json:"role"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`
	Restarts  int       `json:"restarts"`
}

// ConfigResult is the answer to config.get and the changing calls.
type ConfigResult struct {
	Revision uint64        `json:"revision"`
	Config   config.Config `json:"config"`
	Warnings []string      `json:"warnings,omitempty"`
}

// HistoryResult is the answer to config.history.
type HistoryResult struct {
	Revisions []config.Record `json:"revisions"`
	LastGood  uint64          `json:"last_good"`
}

// RollbackParams selects a revision to restore.
type RollbackParams struct {
	Revision uint64 `json:"revision"`
}

// SitePutParams adds or replaces a site. Confirm must be true for a change
// that weakens protection (S-32).
type SitePutParams struct {
	Site    config.Site `json:"site"`
	Confirm bool        `json:"confirm"`
}

// SiteIDParams names a site.
type SiteIDParams struct {
	ID string `json:"id"`
}

// SiteEnabledParams turns a site on or off.
type SiteEnabledParams struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// SecretSetParams sets a secret. The value is write-only (S-35).
type SecretSetParams struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Confirm bool   `json:"confirm"`
}

// SecretStatusResult lists which secrets are set and when, never their values.
type SecretStatusResult struct {
	Secrets []SecretStatus `json:"secrets"`
}

// SecretStatus is one secret's state.
type SecretStatus struct {
	Name  string    `json:"name"`
	Set   bool      `json:"set"`
	SetAt time.Time `json:"set_at,omitzero"`
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
	MethodStatus:         func() any { return &None{} },
	MethodConfigGet:      func() any { return &None{} },
	MethodConfigHistory:  func() any { return &None{} },
	MethodConfigRollback: func() any { return &RollbackParams{} },
	MethodSitePut:        func() any { return &SitePutParams{} },
	MethodSiteRemove:     func() any { return &SiteIDParams{} },
	MethodSiteSetEnabled: func() any { return &SiteEnabledParams{} },
	MethodSecretSet:      func() any { return &SecretSetParams{} },
	MethodSecretStatus:   func() any { return &None{} },
	MethodAuditList:      func() any { return &AuditListParams{} },
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
	return fmt.Sprintf("secret.set(name=%s confirm=%v value=REDACTED)", p.Name, p.Confirm)
}

// GoString hides the value from %#v as well.
func (p SecretSetParams) GoString() string { return p.String() }
