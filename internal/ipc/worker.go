package ipc

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Worker message types, a closed set (ADR-0006).
const (
	// supervisor to worker
	MsgLoad = "load"
	MsgStop = "stop"
	// worker to supervisor
	MsgHello  = "hello"
	MsgLoaded = "loaded"
	MsgFailed = "failed"
)

// Worker roles.
const (
	RoleWeb    = "web"
	RoleTunnel = "tunnel"
)

// WorkerMsg is one message on a worker pipe. Which fields are set depends on
// Type; Validate checks the combination.
type WorkerMsg struct {
	Type     string          `json:"type"`
	Role     string          `json:"role,omitempty"`
	Version  string          `json:"version,omitempty"`
	Revision uint64          `json:"revision,omitempty"`
	Caddy    json.RawMessage `json:"caddy,omitempty"`
	Token    string          `json:"token,omitempty"`
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

// Validate checks that the message has the fields its type needs and none
// it should not carry.
func (m WorkerMsg) Validate() error {
	switch m.Type {
	case MsgHello:
		if m.Role != RoleWeb && m.Role != RoleTunnel {
			return fmt.Errorf("hello with unknown role %q", m.Role)
		}
		if m.Caddy != nil || m.Token != "" {
			return fmt.Errorf("hello carries a payload")
		}
	case MsgLoad:
		if (m.Caddy == nil) == (m.Token == "") {
			return fmt.Errorf("load needs exactly one of caddy and token")
		}
	case MsgLoaded:
		if m.Caddy != nil || m.Token != "" {
			return fmt.Errorf("loaded carries a payload")
		}
	case MsgFailed:
		if m.Reason == "" || len(m.Reason) > MaxReasonLen || m.Caddy != nil || m.Token != "" {
			return fmt.Errorf("failed needs a short reason and no payload")
		}
	case MsgStop:
		if m.Caddy != nil || m.Token != "" || m.Reason != "" {
			return fmt.Errorf("stop carries a payload")
		}
	default:
		return fmt.Errorf("unknown message type %q", m.Type)
	}
	return nil
}

// DecodeWorkerMsg parses and validates one worker message.
func DecodeWorkerMsg(data []byte) (WorkerMsg, error) {
	var m WorkerMsg
	if err := decodeStrict(data, &m); err != nil {
		return WorkerMsg{}, fmt.Errorf("malformed worker message: %w", err)
	}
	if err := m.Validate(); err != nil {
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
