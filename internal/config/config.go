// Package config holds the SoiréeHost configuration schema, its defaults and
// its validation. Validation here is pure: it looks only at the values, never
// at the file system or the network, so it can be fuzzed and so the same rules
// apply wherever a config is checked. File system checks on static roots live
// in internal/sitecheck.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SchemaVersion is the only config version this build understands.
const SchemaVersion = 1

// MaxConfigBytes bounds the size of an encoded config. A real config is a few
// kilobytes; anything near this size is a mistake or an attack.
const MaxConfigBytes = 1 << 20

// MaxSites bounds the number of sites in one config.
const MaxSites = 256

// Defaults (plan S-01, S-15).
const (
	DefaultListen                   = "127.0.0.1:8787"
	DefaultMaxBodyBytes       int64 = 10 << 20 // 10 MB
	DefaultRateLimitPerMinute       = 300
	DefaultMaxHeaderBytes           = 64 << 10 // 64 KB; Cloudflare itself caps request headers at 32 KB
	DefaultReadHeaderTimeout        = 10       // seconds
	DefaultReadTimeout              = 300      // seconds, whole request including body
	DefaultIdleTimeout              = 120      // seconds between requests on a kept-alive connection
)

// Site types.
const (
	TypeStatic = "static"
	TypeProxy  = "proxy"
)

// Config is the whole configuration the supervisor stores and the web worker
// serves. Every field is validated by Validate.
type Config struct {
	Version int          `json:"version"`
	Listen  string       `json:"listen"`
	Server  ServerLimits `json:"server"`
	Sites   []Site       `json:"sites"`
}

// ServerLimits are per listener, not per site: every site in tunnel-token
// mode shares one loopback listener, and these limits apply before the Host
// header has been read (S-15).
type ServerLimits struct {
	MaxHeaderBytes           int `json:"max_header_bytes"`
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds"`
	ReadTimeoutSeconds       int `json:"read_timeout_seconds"`
	IdleTimeoutSeconds       int `json:"idle_timeout_seconds"`
}

// Site is one hosted site: a static folder or a proxied local port.
type Site struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Hostnames []string `json:"hostnames"`
	Type      string   `json:"type"`
	Static    *Static  `json:"static,omitempty"`
	Proxy     *Proxy   `json:"proxy,omitempty"`

	// MaxBodyBytes caps the request body (S-15). Zero means the default.
	MaxBodyBytes int64 `json:"max_body_bytes"`
	// RateLimitPerMinute caps requests per client address (S-15). Zero means
	// the default. It cannot be turned off.
	RateLimitPerMinute int `json:"rate_limit_per_minute"`
	// AllowWellKnown serves the /.well-known/ folder (security.txt, OpenID
	// discovery, app links), the only dot-folder a site can publish. Off by
	// default (S-12); everything inside it still follows the path rules.
	AllowWellKnown bool `json:"allow_well_known"`
	// ResponseHeaders overrides the default security headers (S-16). Keys must
	// be one of ManagedHeaders; an empty value means the header is not sent.
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

// Static serves files from a folder.
type Static struct {
	// Root is an absolute local folder, for example C:\Sites\blog.
	Root string `json:"root"`
	// DirectoryListing shows a file list for folders without an index file.
	// Off by default (S-12).
	DirectoryListing bool `json:"directory_listing"`
}

// Proxy forwards requests to a local app.
type Proxy struct {
	// Target is host:port with an IP literal or "localhost", for example
	// 127.0.0.1:3000.
	Target string `json:"target"`
	// AllowLAN permits a private LAN address as the target. It is a weakening
	// setting: the control panel must confirm it and show a warning (S-10, S-32).
	AllowLAN bool `json:"allow_lan"`
}

// Default returns an empty config with every default filled in.
func Default() Config {
	return Config{
		Version: SchemaVersion,
		Listen:  DefaultListen,
		Server: ServerLimits{
			MaxHeaderBytes:           DefaultMaxHeaderBytes,
			ReadHeaderTimeoutSeconds: DefaultReadHeaderTimeout,
			ReadTimeoutSeconds:       DefaultReadTimeout,
			IdleTimeoutSeconds:       DefaultIdleTimeout,
		},
		Sites: []Site{},
	}
}

// Decode parses a config strictly (unknown fields, trailing data and
// oversized input are errors), normalises it and validates it.
func Decode(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config is larger than %d bytes", MaxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decoding config: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decoding config: unexpected data after the config object")
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Encode writes the config as indented JSON.
func (c Config) Encode() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// Normalize fills zero limits with defaults and puts values into their
// canonical form (lower-case hostnames, IP-literal proxy targets). It never
// makes an invalid value valid by guessing; Validate still has the last word.
func (c *Config) Normalize() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	s := &c.Server
	if s.MaxHeaderBytes == 0 {
		s.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if s.ReadHeaderTimeoutSeconds == 0 {
		s.ReadHeaderTimeoutSeconds = DefaultReadHeaderTimeout
	}
	if s.ReadTimeoutSeconds == 0 {
		s.ReadTimeoutSeconds = DefaultReadTimeout
	}
	if s.IdleTimeoutSeconds == 0 {
		s.IdleTimeoutSeconds = DefaultIdleTimeout
	}
	if c.Sites == nil {
		c.Sites = []Site{}
	}
	for i := range c.Sites {
		site := &c.Sites[i]
		if site.MaxBodyBytes == 0 {
			site.MaxBodyBytes = DefaultMaxBodyBytes
		}
		if site.RateLimitPerMinute == 0 {
			site.RateLimitPerMinute = DefaultRateLimitPerMinute
		}
		for j, h := range site.Hostnames {
			site.Hostnames[j] = strings.ToLower(h)
		}
		if site.Proxy != nil {
			site.Proxy.Target = normalizeTarget(site.Proxy.Target)
		}
	}
}

// Limits on the values Validate accepts.
const (
	maxIDLen           = 32
	maxNameLen         = 64
	maxHostnamesPerSit = 32
	minBodyBytes       = 1 << 10
	maxBodyBytes       = 4 << 30
	maxRatePerMinute   = 100_000
	minHeaderBytes     = 4 << 10
	maxHeaderBytes     = 1 << 20
	maxTimeoutSeconds  = 3600
	maxHeaderValueLen  = 1024
)

// FieldError is one validation problem, with the path of the field.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

type problems []error

func (p *problems) add(field, format string, args ...any) {
	*p = append(*p, &FieldError{Field: field, Msg: fmt.Sprintf(format, args...)})
}

// Validate checks every field and returns all problems joined, or nil.
func (c Config) Validate() error {
	var p problems
	if c.Version != SchemaVersion {
		p.add("version", "must be %d", SchemaVersion)
	}
	listen, err := ParseListen(c.Listen)
	if err != nil {
		p.add("listen", "%v", err)
	}
	c.Server.validate(&p)

	if len(c.Sites) > MaxSites {
		p.add("sites", "at most %d sites", MaxSites)
	}
	ids := map[string]bool{}
	hosts := map[string]int{} // hostname -> index of the first site using it
	for i, s := range c.Sites {
		field := fmt.Sprintf("sites[%d]", i)
		s.validate(field, &p, listen.Port())
		if s.ID != "" {
			if ids[s.ID] {
				p.add(field+".id", "duplicate site id %q", s.ID)
			}
			ids[s.ID] = true
		}
		for j, h := range s.Hostnames {
			other, ok := hosts[h]
			if !ok {
				hosts[h] = i
				continue
			}
			if other != i { // repeats inside one site are reported by Site.validate
				p.add(fmt.Sprintf("%s.hostnames[%d]", field, j), "hostname is already used by site %q", c.Sites[other].ID)
			}
		}
	}
	return errors.Join(p...)
}

func (s ServerLimits) validate(p *problems) {
	if s.MaxHeaderBytes < minHeaderBytes || s.MaxHeaderBytes > maxHeaderBytes {
		p.add("server.max_header_bytes", "must be between %d and %d", minHeaderBytes, maxHeaderBytes)
	}
	for _, t := range []struct {
		name string
		v    int
	}{
		{"server.read_header_timeout_seconds", s.ReadHeaderTimeoutSeconds},
		{"server.read_timeout_seconds", s.ReadTimeoutSeconds},
		{"server.idle_timeout_seconds", s.IdleTimeoutSeconds},
	} {
		if t.v < 1 || t.v > maxTimeoutSeconds {
			p.add(t.name, "must be between 1 and %d seconds", maxTimeoutSeconds)
		}
	}
	if s.ReadHeaderTimeoutSeconds > s.ReadTimeoutSeconds {
		p.add("server.read_header_timeout_seconds", "must not be longer than read_timeout_seconds")
	}
}

func (s Site) validate(field string, p *problems, listenPort uint16) {
	if !validID(s.ID) {
		p.add(field+".id", "must be 1 to %d characters from a-z, 0-9 and '-', starting with a letter or digit", maxIDLen)
	}
	if err := validName(s.Name); err != nil {
		p.add(field+".name", "%v", err)
	}
	if len(s.Hostnames) > maxHostnamesPerSit {
		p.add(field+".hostnames", "at most %d hostnames", maxHostnamesPerSit)
	}
	seen := map[string]bool{}
	for j, h := range s.Hostnames {
		hf := fmt.Sprintf("%s.hostnames[%d]", field, j)
		if err := ValidateHostname(h); err != nil {
			p.add(hf, "%v", err)
		}
		if seen[h] {
			p.add(hf, "duplicate hostname")
		}
		seen[h] = true
	}

	switch s.Type {
	case TypeStatic:
		if s.Static == nil {
			p.add(field+".static", "required for a static site")
		} else if err := ValidateRootSyntax(s.Static.Root); err != nil {
			p.add(field+".static.root", "%v", err)
		}
		if s.Proxy != nil {
			p.add(field+".proxy", "not allowed on a static site")
		}
	case TypeProxy:
		if s.Proxy == nil {
			p.add(field+".proxy", "required for a proxy site")
		} else if _, err := ParseTarget(s.Proxy.Target, s.Proxy.AllowLAN, listenPort); err != nil {
			p.add(field+".proxy.target", "%v", err)
		}
		if s.Static != nil {
			p.add(field+".static", "not allowed on a proxy site")
		}
	default:
		p.add(field+".type", "must be %q or %q", TypeStatic, TypeProxy)
	}

	if s.MaxBodyBytes < minBodyBytes || s.MaxBodyBytes > maxBodyBytes {
		p.add(field+".max_body_bytes", "must be between %d and %d", minBodyBytes, int64(maxBodyBytes))
	}
	if s.RateLimitPerMinute < 1 || s.RateLimitPerMinute > maxRatePerMinute {
		p.add(field+".rate_limit_per_minute", "must be between 1 and %d", maxRatePerMinute)
	}
	for k, v := range s.ResponseHeaders {
		hf := field + ".response_headers"
		if _, ok := defaultHeaders[k]; !ok {
			p.add(hf, "%q is not a header that can be changed; allowed: %s", k, strings.Join(ManagedHeaders(), ", "))
			continue
		}
		if err := validHeaderValue(v); err != nil {
			p.add(hf+"."+k, "%v", err)
		}
	}
}

// Warnings lists settings that are allowed but weaken protection, in words
// the control panel can show next to the setting (S-10, S-14 style).
func (c Config) Warnings() []string {
	var w []string
	for _, s := range c.Sites {
		if s.Type != TypeProxy || s.Proxy == nil || !s.Proxy.AllowLAN {
			continue
		}
		t, err := ParseTarget(s.Proxy.Target, true, 0)
		if err == nil && !t.Addr().IsLoopback() {
			w = append(w, fmt.Sprintf("Site %q forwards to %s on your local network. Anything that site exposes is reachable from the internet.", s.ID, s.Proxy.Target))
		}
	}
	return w
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLen || id[0] == '-' {
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

func validName(n string) error {
	if strings.TrimSpace(n) == "" {
		return errors.New("must not be empty")
	}
	if len([]rune(n)) > maxNameLen {
		return fmt.Errorf("at most %d characters", maxNameLen)
	}
	if err := checkPrintable(n); err != nil {
		return err
	}
	return nil
}
