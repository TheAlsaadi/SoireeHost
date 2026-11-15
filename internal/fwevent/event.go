// Package fwevent defines the firewall event the web worker writes to
// firewall.log and the supervisor reads back for the firewall.events control
// method (ADR-0008). Every field holds attacker-influenced data, so an event
// is built only through Clean, which keeps it inside the shape Validate
// accepts, and the reader validates every line again: a compromised worker
// may write anything into its own log folder.
package fwevent

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/redact"
)

// Modes and actions, closed sets.
const (
	ModeBlock  = "block"
	ModeDetect = "detect"

	ActionBlocked  = "blocked"
	ActionDetected = "detected"
)

// Limits on an event's fields.
const (
	MaxRules      = 10
	MaxMsgLen     = 160
	MaxURILen     = 2048
	MaxMethodLen  = 16
	MaxWhere      = 8
	maxWhereLen   = 32
	maxRuleID     = 999_999_999
	maxLevel      = 4
	PlaceholderMs = "matched"
)

// Severities as Coraza names them.
var severities = []string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}

// Event is one request the firewall blocked or, in Detect only, would have
// blocked. It never holds headers, cookies, bodies, matched data or the user
// agent (S-18, S-40).
type Event struct {
	Time          time.Time `json:"time"`
	Site          string    `json:"site"`
	Mode          string    `json:"mode"`
	Action        string    `json:"action"`
	Status        int       `json:"status"`
	ParanoiaLevel int       `json:"paranoia_level"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	URI           string    `json:"uri"`
	ClientIP      string    `json:"client_ip"`
	Rules         []Rule    `json:"rules"`
}

// Rule is one matched rule: its id, severity and message, and the
// collections the match was in. The key inside a collection (a parameter,
// cookie or header name) and the matched value are never kept.
type Rule struct {
	ID       int      `json:"id"`
	Severity string   `json:"severity"`
	Msg      string   `json:"msg"`
	Where    []string `json:"where,omitempty"`
}

// Clean returns e with every field forced into the shape Validate accepts:
// the URI masked (S-18) and cut, an invalid host or address dropped, rules
// capped. matched lists the values the rules matched; a message containing
// any of them is replaced, since a rule message may expand variables.
func (e Event) Clean(matched []string) Event {
	out := Event{
		Time:          e.Time.UTC(),
		Site:          e.Site,
		Mode:          e.Mode,
		Action:        e.Action,
		Status:        e.Status,
		ParanoiaLevel: e.ParanoiaLevel,
		Method:        cleanMethod(e.Method),
		Host:          cleanHost(e.Host),
		URI:           CleanURI(e.URI),
		ClientIP:      cleanIP(e.ClientIP),
		Rules:         []Rule{},
	}
	for _, r := range e.Rules {
		if len(out.Rules) == MaxRules {
			break
		}
		if r.ID < 1 || r.ID > maxRuleID {
			continue
		}
		c := Rule{ID: r.ID, Severity: r.Severity, Msg: cleanMsg(r.Msg, matched)}
		if !slices.Contains(severities, c.Severity) {
			c.Severity = ""
		}
		for _, w := range r.Where {
			if len(c.Where) == MaxWhere {
				break
			}
			if validWhere(w) && !slices.Contains(c.Where, w) {
				c.Where = append(c.Where, w)
			}
		}
		out.Rules = append(out.Rules, c)
	}
	return out
}

// Validate checks an event as read back from the log.
func (e Event) Validate() error {
	if e.Time.IsZero() {
		return errors.New("no time")
	}
	if !config.ValidSiteID(e.Site) {
		return errors.New("bad site id")
	}
	switch {
	case e.Mode == ModeBlock && e.Action == ActionBlocked:
		if e.Status != 400 && e.Status != 403 && e.Status != 413 {
			return fmt.Errorf("status %d is not a firewall status", e.Status)
		}
	case e.Mode == ModeDetect && e.Action == ActionDetected:
		if e.Status != 0 {
			return errors.New("a detected request has no status")
		}
	default:
		return errors.New("bad mode or action")
	}
	if e.ParanoiaLevel < 1 || e.ParanoiaLevel > maxLevel {
		return errors.New("bad paranoia level")
	}
	if e.Method != cleanMethod(e.Method) || e.Method == "" {
		return errors.New("bad method")
	}
	if e.Host != cleanHost(e.Host) {
		return errors.New("bad host")
	}
	// empty only when the request carried no target (never through the
	// guard, but Clean must always produce what Validate accepts: FuzzClean)
	if e.URI != CleanURI(e.URI) {
		return errors.New("bad uri")
	}
	if e.ClientIP != cleanIP(e.ClientIP) {
		return errors.New("bad client address")
	}
	if e.Rules == nil || len(e.Rules) > MaxRules {
		return errors.New("bad rule list")
	}
	for _, r := range e.Rules {
		if r.ID < 1 || r.ID > maxRuleID {
			return errors.New("bad rule id")
		}
		if r.Severity != "" && !slices.Contains(severities, r.Severity) {
			return errors.New("bad severity")
		}
		if !validMsg(r.Msg) {
			return errors.New("bad rule message")
		}
		if len(r.Where) > MaxWhere {
			return errors.New("too many collections")
		}
		for _, w := range r.Where {
			if !validWhere(w) {
				return errors.New("bad collection name")
			}
		}
	}
	return nil
}

// CleanURI makes a request target safe to store: bytes outside printable
// ASCII are percent-encoded, every query value is masked (S-18), and the
// result is at most MaxURILen bytes. If it is too long, the path is cut and a
// query, if any, is masked whole. CleanURI(CleanURI(u)) == CleanURI(u).
func CleanURI(u string) string {
	var b strings.Builder
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c <= 0x20 || c >= 0x7f {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	masked := redact.URI(b.String())
	if len(masked) <= MaxURILen {
		return masked
	}
	base, _, hasQuery := strings.Cut(masked, "?")
	tail := ""
	if hasQuery {
		tail = "?" + redact.Masked
	}
	if len(base) > MaxURILen-len(tail) {
		base = base[:MaxURILen-len(tail)]
	}
	return base + tail
}

func cleanMethod(m string) string {
	if m == "" || len(m) > MaxMethodLen {
		return "OTHER"
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return "OTHER"
		}
	}
	return m
}

func cleanHost(h string) string {
	h = strings.ToLower(h)
	if h == "" || config.ValidateHostname(h) != nil {
		return ""
	}
	return h
}

func cleanIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.Unmap().String()
}

func cleanMsg(m string, matched []string) string {
	if !validMsg(m) || m == "" {
		return PlaceholderMs
	}
	low := strings.ToLower(m)
	for _, v := range matched {
		// short values ("1", "a") appear in ordinary messages by chance
		if len(v) >= 3 && strings.Contains(low, strings.ToLower(v)) {
			return PlaceholderMs
		}
	}
	return m
}

func validMsg(m string) bool {
	if m == "" || len(m) > MaxMsgLen {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 0x20 || m[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validWhere accepts a Coraza collection name: rule-authored, upper-case.
func validWhere(w string) bool {
	if w == "" || len(w) > maxWhereLen {
		return false
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if (c < 'A' || c > 'Z') && c != '_' {
			return false
		}
	}
	return true
}
