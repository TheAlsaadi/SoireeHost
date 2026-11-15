package config

import "fmt"

// Firewall modes (S-14, ADR-0008).
const (
	FirewallBlock  = "block"
	FirewallDetect = "detect"
	FirewallOff    = "off"
)

// DefaultParanoiaLevel is the CRS paranoia level every new site starts at
// (S-14; owner decision of 15 Nov 2026).
const DefaultParanoiaLevel = 1

// MaxParanoiaLevel is the highest CRS paranoia level.
const MaxParanoiaLevel = 4

// FirewallInspectBytes is how much of a request body the firewall inspects.
// In Block mode a larger body is refused with 413 (owner decision of 15 Nov
// 2026); in Detect only the rest passes uninspected.
const FirewallInspectBytes int64 = 16 << 20

// Firewall is a site's web application firewall setting.
type Firewall struct {
	// Mode is block, detect (log only) or off. Empty means block.
	Mode string `json:"mode"`
	// ParanoiaLevel is the CRS paranoia level, 1 to 4. Zero means 1.
	ParanoiaLevel int `json:"paranoia_level"`
}

func (f *Firewall) normalize() {
	if f.Mode == "" {
		f.Mode = FirewallBlock
	}
	if f.ParanoiaLevel == 0 {
		f.ParanoiaLevel = DefaultParanoiaLevel
	}
}

func (f Firewall) validate(field string, p *problems) {
	if FirewallStrength(f.Mode) < 0 {
		p.add(field+".mode", "must be %q, %q or %q", FirewallBlock, FirewallDetect, FirewallOff)
	}
	// zero is the default, as Normalize makes it
	if f.ParanoiaLevel < 0 || f.ParanoiaLevel > MaxParanoiaLevel {
		p.add(field+".paranoia_level", "must be between 1 and %d", MaxParanoiaLevel)
	}
}

// Level is the paranoia level in force: zero means the default.
func (f Firewall) Level() int {
	if f.ParanoiaLevel == 0 {
		return DefaultParanoiaLevel
	}
	return f.ParanoiaLevel
}

// EffectiveMode is the mode in force: empty means block.
func (f Firewall) EffectiveMode() string {
	if f.Mode == "" {
		return FirewallBlock
	}
	return f.Mode
}

// FirewallStrength orders the modes: block 2, detect 1, off 0, and -1 for
// anything else. An empty mode counts as block, as Normalize makes it.
func FirewallStrength(mode string) int {
	switch mode {
	case FirewallBlock, "":
		return 2
	case FirewallDetect:
		return 1
	case FirewallOff:
		return 0
	}
	return -1
}

// FirewallWeakenings lists the sites whose firewall next makes weaker than
// cur does (S-32, ADR-0008): a site whose mode goes down, or a site new in
// next that starts below Block, the default every new site gets.
func FirewallWeakenings(cur, next Config) []string {
	have := map[string]int{}
	for _, s := range cur.Sites {
		have[s.ID] = FirewallStrength(s.Firewall.Mode)
	}
	var out []string
	for _, s := range next.Sites {
		was, ok := have[s.ID]
		if !ok {
			was = FirewallStrength(FirewallBlock)
		}
		if FirewallStrength(s.Firewall.Mode) < was {
			out = append(out, s.ID)
		}
	}
	return out
}

// firewallWarnings are the standing warnings for one site (S-14).
func firewallWarnings(s Site) []string {
	switch s.Firewall.EffectiveMode() {
	case FirewallOff:
		return []string{fmt.Sprintf("Site %q has its firewall turned off. Attacks reach the site unchecked.", s.ID)}
	case FirewallDetect:
		return []string{fmt.Sprintf("Site %q has its firewall set to Detect only. Attacks are logged but not blocked.", s.ID)}
	}
	if s.MaxBodyBytes > FirewallInspectBytes {
		return []string{fmt.Sprintf("Site %q accepts request bodies up to %d MB, but while its firewall blocks, bodies over %d MB are refused.",
			s.ID, s.MaxBodyBytes>>20, FirewallInspectBytes>>20)}
	}
	return nil
}
