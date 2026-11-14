package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// Worker message types, a closed set (ADR-0006, ADR-0007).
const (
	// supervisor to worker
	MsgLoad = "load"
	MsgStop = "stop"
	// worker to supervisor
	MsgHello  = "hello"
	MsgLoaded = "loaded"
	MsgFailed = "failed"
	MsgStatus = "status" // tunnel launcher only
)

// Worker roles.
const (
	RoleWeb    = "web"
	RoleTunnel = "tunnel"
)

// WorkerMsg is one message on a worker pipe. Which fields may be set depends
// on the message type and on the pipe's role: Caddy only in a load on the web
// pipe, Tunnel only in a load on the tunnel pipe, Report only in a status on
// the tunnel pipe (review finding SE-21). ValidateFor checks the combination.
type WorkerMsg struct {
	Type     string          `json:"type"`
	Role     string          `json:"role,omitempty"`
	Version  string          `json:"version,omitempty"`
	Revision uint64          `json:"revision,omitempty"`
	Caddy    json.RawMessage `json:"caddy,omitempty"`
	Tunnel   *TunnelPlan     `json:"tunnel,omitempty"`
	Report   *TunnelReport   `json:"report,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

// MaxReasonLen bounds a worker's failure reason.
const MaxReasonLen = 2048

// CutReason makes an error text a valid failure reason: valid UTF-8, at
// most MaxReasonLen bytes, cut on a character boundary, never empty. JSON
// turns an invalid or split byte into a three-byte replacement character,
// which pushed a reason cut at a byte count over the limit; the supervisor
// then refused the worker's failed message, treated the worker as down and
// restored nothing (review finding GO-1).
func CutReason(s string) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) > MaxReasonLen {
		end := MaxReasonLen
		for end > 0 && !utf8.RuneStart(s[end]) {
			end--
		}
		s = s[:end]
	}
	if s == "" {
		s = "unknown error"
	}
	return s
}

func (m WorkerMsg) hasPayload() bool { return m.Caddy != nil || m.Tunnel != nil || m.Report != nil }

// ValidateFor checks that the message has the fields its type needs on a
// pipe of the given role, and none it should not carry.
func (m WorkerMsg) ValidateFor(role string) error {
	if role != RoleWeb && role != RoleTunnel {
		return fmt.Errorf("unknown role %q", role)
	}
	switch m.Type {
	case MsgHello:
		if m.Role != role {
			return fmt.Errorf("hello from role %q on the %s pipe", m.Role, role)
		}
		if m.hasPayload() {
			return errors.New("hello carries a payload")
		}
	case MsgLoad:
		if m.Report != nil {
			return errors.New("load carries a status report")
		}
		switch role {
		case RoleWeb:
			if m.Tunnel != nil {
				return errors.New("a tunnel plan sent to the web worker")
			}
			if !isJSONObject(m.Caddy) {
				return errors.New("a web load needs a Caddy config object")
			}
		case RoleTunnel:
			if m.Caddy != nil {
				return errors.New("a Caddy config sent to the tunnel launcher")
			}
			if m.Tunnel == nil {
				return errors.New("a tunnel load needs a tunnel plan")
			}
			if err := m.Tunnel.Validate(); err != nil {
				return err
			}
		}
	case MsgLoaded:
		if m.hasPayload() {
			return errors.New("loaded carries a payload")
		}
	case MsgFailed:
		if m.Reason == "" || len(m.Reason) > MaxReasonLen || m.hasPayload() {
			return errors.New("failed needs a short reason and no payload")
		}
	case MsgStatus:
		if role != RoleTunnel {
			return errors.New("status reports come only from the tunnel launcher")
		}
		if m.Caddy != nil || m.Tunnel != nil || m.Report == nil {
			return errors.New("status needs a report and nothing else")
		}
		if err := m.Report.Validate(); err != nil {
			return err
		}
	case MsgStop:
		if m.hasPayload() || m.Reason != "" {
			return errors.New("stop carries a payload")
		}
	default:
		return fmt.Errorf("unknown message type %q", m.Type)
	}
	return nil
}

func isJSONObject(b json.RawMessage) bool {
	b = bytes.TrimSpace(b)
	return len(b) >= 2 && b[0] == '{' && json.Valid(b)
}

// DecodeWorkerMsg parses and validates one worker message for a pipe of the
// given role.
func DecodeWorkerMsg(data []byte, role string) (WorkerMsg, error) {
	var m WorkerMsg
	if err := decodeStrict(data, &m); err != nil {
		return WorkerMsg{}, fmt.Errorf("malformed worker message: %w", err)
	}
	if err := m.ValidateFor(role); err != nil {
		return WorkerMsg{}, err
	}
	return m, nil
}

// String describes a message without its payload, so a tunnel token can
// never end up in a log line by way of fmt.
func (m WorkerMsg) String() string {
	return fmt.Sprintf("%s(role=%s revision=%d)", m.Type, m.Role, m.Revision)
}

// GoString keeps %#v from printing the token either.
func (m WorkerMsg) GoString() string { return m.String() }

// ----- Tunnel plan (supervisor to tunnel launcher) -----

// TunnelPlan is the whole desired state of the tunnels: which cloudflared
// processes should run. The launcher makes it so; each new plan replaces the
// last, so the last one sent always wins (review finding GO-6).
type TunnelPlan struct {
	// Offline stops every tunnel (the offline switch).
	Offline bool `json:"offline"`
	// Token runs the token tunnel when set (S-50). It reaches cloudflared
	// only through its environment (S-23).
	Token string `json:"token,omitempty"`
	// ListenPort is the web worker's main loopback port, the only service
	// the token tunnel's dashboard ingress should name.
	ListenPort int `json:"listen_port"`
	// MetricsPort is the token tunnel's loopback metrics port.
	MetricsPort int `json:"metrics_port"`
	// Shares are the quick shares.
	Shares []SharePlan `json:"shares"`
}

// SharePlan is one quick share: cloudflared forwards to 127.0.0.1:Port.
type SharePlan struct {
	SiteID      string `json:"site_id"`
	Port        int    `json:"port"`
	MetricsPort int    `json:"metrics_port"`
}

// Validate checks the plan: ports in range and distinct, at most
// config.MaxQuickShares shares, valid site ids, and a token in the tunnel
// token format if one is set.
func (p TunnelPlan) Validate() error {
	if p.Token != "" {
		if _, err := config.ValidateTunnelToken(p.Token); err != nil {
			return errors.New("the tunnel plan carries something that is not a tunnel token")
		}
	}
	if len(p.Shares) > config.MaxQuickShares {
		return fmt.Errorf("at most %d quick shares", config.MaxQuickShares)
	}
	seen := map[int]bool{}
	port := func(n int) error {
		if n < 1024 || n > 65535 || seen[n] {
			return fmt.Errorf("port %d is out of range or used twice", n)
		}
		seen[n] = true
		return nil
	}
	if err := port(p.ListenPort); err != nil {
		return err
	}
	if err := port(p.MetricsPort); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, s := range p.Shares {
		if !validSiteID(s.SiteID) || ids[s.SiteID] {
			return fmt.Errorf("bad or repeated site id %q", s.SiteID)
		}
		ids[s.SiteID] = true
		if err := port(s.Port); err != nil {
			return err
		}
		if err := port(s.MetricsPort); err != nil {
			return err
		}
	}
	return nil
}

// String prints the plan without its token.
func (p TunnelPlan) String() string {
	return fmt.Sprintf("plan(offline=%v token_set=%v shares=%d)", p.Offline, p.Token != "", len(p.Shares))
}

// GoString keeps %#v from printing the token.
func (p TunnelPlan) GoString() string { return p.String() }

func validSiteID(id string) bool {
	if id == "" || len(id) > 32 || id[0] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ----- Tunnel report (tunnel launcher to supervisor) -----

// Tunnel kinds.
const (
	TunnelKindToken = "token"
	TunnelKindQuick = "quick"
)

// Tunnel states (ADR-0007).
const (
	TunnelStarting     = "starting"
	TunnelConnected    = "connected"
	TunnelReconnecting = "reconnecting"
	TunnelDown         = "down"
	TunnelRefused      = "refused"
)

// Tunnel problem codes, a closed set: the launcher never passes cloudflared's
// own words to the supervisor, so no reason can echo the token (R-21).
const (
	ProblemBinaryMissing      = "binary_missing"
	ProblemBinaryMismatch     = "binary_mismatch"
	ProblemUnexpectedListener = "unexpected_listener"
	ProblemStartFailed        = "start_failed"
	ProblemExited             = "exited"
	ProblemIngressOutside     = "ingress_outside"
)

var (
	tunnelStates   = []string{TunnelStarting, TunnelConnected, TunnelReconnecting, TunnelDown, TunnelRefused}
	tunnelProblems = []string{ProblemBinaryMissing, ProblemBinaryMismatch, ProblemUnexpectedListener,
		ProblemStartFailed, ProblemExited, ProblemIngressOutside}
)

// MaxConnections bounds the reported edge connections of one tunnel
// (cloudflared opens four).
const MaxConnections = 16

// TunnelReport is the launcher's view of every tunnel it runs.
type TunnelReport struct {
	Tunnels []TunnelState `json:"tunnels"`
}

// TunnelState is one cloudflared process.
type TunnelState struct {
	Kind        string    `json:"kind"`
	SiteID      string    `json:"site_id,omitempty"`
	State       string    `json:"state"`
	Connections int       `json:"connections"`
	Hostname    string    `json:"hostname,omitempty"`
	Problems    []string  `json:"problems,omitempty"`
	Since       time.Time `json:"since"`
}

// Validate checks a report against the closed sets.
func (r TunnelReport) Validate() error {
	if len(r.Tunnels) > 1+config.MaxQuickShares {
		return errors.New("too many tunnels in a report")
	}
	sites := map[string]bool{}
	tokens := 0
	for _, t := range r.Tunnels {
		switch t.Kind {
		case TunnelKindToken:
			tokens++
			if t.SiteID != "" || t.Hostname != "" {
				return errors.New("the token tunnel has no site and no quick hostname")
			}
		case TunnelKindQuick:
			if !validSiteID(t.SiteID) || sites[t.SiteID] {
				return fmt.Errorf("bad or repeated site id %q", t.SiteID)
			}
			sites[t.SiteID] = true
			if t.Hostname != "" && !config.ValidQuickShareHostname(t.Hostname) {
				return errors.New("a quick share hostname that is not under trycloudflare.com")
			}
		default:
			return fmt.Errorf("unknown tunnel kind %q", t.Kind)
		}
		if !slices.Contains(tunnelStates, t.State) {
			return fmt.Errorf("unknown tunnel state %q", t.State)
		}
		if t.Connections < 0 || t.Connections > MaxConnections {
			return errors.New("connection count out of range")
		}
		if len(t.Problems) > len(tunnelProblems) {
			return errors.New("too many problems")
		}
		for _, p := range t.Problems {
			if !slices.Contains(tunnelProblems, p) {
				return fmt.Errorf("unknown problem %q", p)
			}
		}
	}
	if tokens > 1 {
		return errors.New("more than one token tunnel")
	}
	return nil
}
