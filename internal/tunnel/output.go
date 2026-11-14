package tunnel

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
)

// MaxLineBytes caps one line of cloudflared output; longer lines are cut.
const MaxLineBytes = 64 << 10

// cloudflared's JSON log line (zerolog with --output json; field names
// checked against cloudflared 2026.11.0).
type logLine struct {
	Level     string `json:"level"`
	Message   string `json:"message"`
	ConnIndex *int   `json:"connIndex"`
	Config    string `json:"config"`
}

// Messages the parser acts on (cloudflared 2026.11.0).
const (
	msgRegistered   = "Registered tunnel connection"
	msgUnregistered = "Unregistered tunnel connection"
	msgNewConfig    = "Updated to new configuration"
)

// quickURLRe is the table row in which cloudflared prints a quick tunnel's
// address.
var quickURLRe = regexp.MustCompile(`^\|\s+https://([a-z0-9-]{1,63}\.trycloudflare\.com)\s+\|$`)

// outputState is what one cloudflared process has said about itself. It is
// built only from that process's own stderr, never from its metrics server,
// which any local process could impersonate (ADR-0007).
type outputState struct {
	quick      bool
	listenPort int

	conns         map[int]bool
	everConnected bool
	// hostname is the quick share address: the first one printed before
	// the first registered connection. Later text cannot change it.
	hostname       string
	hostnameClosed bool
	// ingressOutside is set when the dashboard's ingress names a service
	// other than SoiréeHost's own listener (token mode only).
	ingressOutside bool
}

func newOutputState(quick bool, listenPort int) *outputState {
	return &outputState{quick: quick, listenPort: listenPort, conns: map[int]bool{}}
}

// connections is the number of registered edge connections.
func (s *outputState) connections() int { return len(s.conns) }

// feed takes one line of output and reports whether the state changed.
func (s *outputState) feed(line []byte) bool {
	var l logLine
	if err := json.Unmarshal(line, &l); err != nil {
		return false
	}
	switch {
	case l.Message == msgRegistered && l.ConnIndex != nil:
		s.hostnameClosed = true
		if s.conns[*l.ConnIndex] || len(s.conns) >= 16 {
			return false
		}
		s.conns[*l.ConnIndex] = true
		s.everConnected = true
		return true
	case l.Message == msgUnregistered && l.ConnIndex != nil:
		if !s.conns[*l.ConnIndex] {
			return false
		}
		delete(s.conns, *l.ConnIndex)
		return true
	case l.Message == msgNewConfig && !s.quick:
		outside := ingressOutside(l.Config, s.listenPort)
		changed := outside != s.ingressOutside
		s.ingressOutside = outside
		return changed
	case s.quick && !s.hostnameClosed && s.hostname == "":
		m := quickURLRe.FindStringSubmatch(l.Message)
		if m == nil || !config.ValidQuickShareHostname(m[1]) {
			return false
		}
		s.hostname = m[1]
		s.hostnameClosed = true
		return true
	}
	return false
}

// remoteConfig is the part of a remotely managed tunnel's configuration the
// launcher checks.
type remoteConfig struct {
	Ingress []struct {
		Service string `json:"service"`
	} `json:"ingress"`
	WarpRouting struct {
		Enabled bool `json:"enabled"`
	} `json:"warp-routing"`
}

// ingressOutside reports whether a remote configuration sends traffic
// anywhere but SoiréeHost's own listener: a service other than
// http://127.0.0.1:PORT, http://localhost:PORT or http://[::1]:PORT, an
// http_status response, or private network routing (WARP). A configuration
// that cannot be read counts as outside (fail closed: it only warns).
func ingressOutside(cfg string, listenPort int) bool {
	var rc remoteConfig
	if err := json.Unmarshal([]byte(cfg), &rc); err != nil {
		return true
	}
	if rc.WarpRouting.Enabled {
		return true
	}
	port := strconv.Itoa(listenPort)
	allowed := map[string]bool{}
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		allowed["http://"+host+":"+port] = true
		allowed["http://"+host+":"+port+"/"] = true
	}
	for _, r := range rc.Ingress {
		svc := strings.ToLower(strings.TrimSpace(r.Service))
		if allowed[svc] {
			continue
		}
		if code, ok := strings.CutPrefix(svc, "http_status:"); ok {
			if n, err := strconv.Atoi(code); err == nil && n >= 100 && n <= 599 {
				continue
			}
		}
		return true
	}
	return false
}

// scrubber hides a tunnel token and its secret parts in cloudflared's
// output before it is written anywhere (review finding R-21).
type scrubber struct {
	secrets [][]byte
}

const redacted = "[redacted]"

func newScrubber(token string) scrubber {
	if token == "" {
		return scrubber{}
	}
	var s scrubber
	add := func(v string) {
		if len(v) >= 8 {
			s.secrets = append(s.secrets, []byte(v))
		}
	}
	add(token)
	if parts, err := config.ValidateTunnelToken(token); err == nil {
		add(parts.Secret)
		add(parts.AccountTag)
		if raw, err := base64.StdEncoding.DecodeString(parts.Secret); err == nil {
			add(base64.RawStdEncoding.EncodeToString(raw))
			add(base64.URLEncoding.EncodeToString(raw))
			add(base64.RawURLEncoding.EncodeToString(raw))
		}
	}
	return s
}

// scrub returns line with every secret replaced. Longer secrets go first, so
// a part inside the token never leaves the rest of the token behind.
func (s scrubber) scrub(line []byte) []byte {
	for _, sec := range s.secrets {
		if bytes.Contains(line, sec) {
			line = bytes.ReplaceAll(line, sec, []byte(redacted))
		}
	}
	return line
}

// readLines calls fn for each line of r, without its line ending. Lines
// longer than MaxLineBytes are cut to that length; the rest of such a line
// is skipped. It returns when r ends or fails.
func readLines(r io.Reader, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, MaxLineBytes)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			fn(bytes.TrimRight(line, "\r\n"))
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			continue
		}
		if len(line) > 0 {
			fn(bytes.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
