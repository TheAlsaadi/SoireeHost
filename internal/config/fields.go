package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ----- Listen address (S-01) -----

// ParseListen accepts only 127.0.0.1:port or [::1]:port with a port from
// 1024 to 65535. Host names (including "localhost"), wildcard addresses and a
// bare ":port" are refused, so the listener can never be anything but
// loopback.
func ParseListen(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, errors.New("must be 127.0.0.1:PORT or [::1]:PORT")
	}
	if !isStrictLoopback(ap.Addr()) {
		return netip.AddrPort{}, errors.New("only 127.0.0.1 or ::1 may be used; SoiréeHost never listens on another address")
	}
	if ap.Port() < 1024 {
		return netip.AddrPort{}, errors.New("port must be between 1024 and 65535")
	}
	return ap, nil
}

// isStrictLoopback is true only for 127.0.0.1 and ::1 (not other 127/8
// addresses, not IPv4-mapped forms, not zones).
func isStrictLoopback(a netip.Addr) bool {
	if a.Zone() != "" {
		return false
	}
	return a == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || a == netip.IPv6Loopback()
}

// IsStrictLoopback reports whether a is 127.0.0.1 or ::1.
func IsStrictLoopback(a netip.Addr) bool { return isStrictLoopback(a) }

// ----- Proxy target (S-10) -----

func normalizeTarget(t string) string {
	host, port, err := splitHostPort(t)
	if err != nil {
		return t
	}
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1:" + port
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return t
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(p, 10) != port {
		return t
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(p)).String()
}

func splitHostPort(t string) (host, port string, err error) {
	if strings.HasPrefix(t, "[") {
		end := strings.Index(t, "]")
		if end < 0 || !strings.HasPrefix(t[end+1:], ":") {
			return "", "", errors.New("bad address")
		}
		return t[1:end], t[end+2:], nil
	}
	i := strings.LastIndex(t, ":")
	if i < 0 || strings.Count(t, ":") != 1 {
		return "", "", errors.New("bad address")
	}
	return t[:i], t[i+1:], nil
}

// ParseTarget validates a proxy target. Allowed: 127.0.0.1 or ::1, or, with
// allowLAN, a private LAN address (10/8, 172.16/12, 192.168/16, fc00::/7).
// Always refused: link-local, unspecified, multicast, broadcast, public
// addresses, other loopback addresses, host names, and any of SoiréeHost's
// own loopback ports (the listener, quick-share listeners and cloudflared
// metrics servers; S-10, R-06).
func ParseTarget(t string, allowLAN bool, own ...uint16) (netip.AddrPort, error) {
	host, portStr, err := splitHostPort(t)
	if err != nil || host == "" || portStr == "" {
		return netip.AddrPort{}, errors.New("must be IP:PORT, for example 127.0.0.1:3000")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portStr {
		return netip.AddrPort{}, errors.New("port must be a number from 1 to 65535")
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, errors.New("must be an IP address (or localhost), not a host name")
	}
	if a.Zone() != "" {
		return netip.AddrPort{}, errors.New("addresses with a zone are not allowed")
	}
	a = a.Unmap()
	ap := netip.AddrPortFrom(a, uint16(port))
	switch {
	case a.IsUnspecified():
		return netip.AddrPort{}, errors.New("0.0.0.0 and :: are not addresses an app can be reached on")
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast():
		return netip.AddrPort{}, errors.New("link-local addresses (169.254.x.x, fe80::) are never allowed")
	case a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.AddrPort{}, errors.New("multicast and broadcast addresses are not allowed")
	case a.IsLoopback():
		if !isStrictLoopback(a) {
			return netip.AddrPort{}, errors.New("use 127.0.0.1 or ::1 for this PC")
		}
		if slices.Contains(own, ap.Port()) {
			return netip.AddrPort{}, errors.New("that is one of SoiréeHost's own ports")
		}
	case a.IsPrivate():
		if !allowLAN {
			return netip.AddrPort{}, errors.New("LAN addresses need the per-site LAN opt-in")
		}
	default:
		return netip.AddrPort{}, errors.New("only this PC (127.0.0.1, ::1) or, with the LAN opt-in, a private LAN address is allowed")
	}
	return ap, nil
}

// ----- Hostnames (S-06) -----

// ValidateHostname accepts a lower-case DNS name of at least two labels made
// of a-z, 0-9 and '-' (internationalised names in their xn-- form). Wildcards,
// IP addresses, trailing dots and ports are refused.
func ValidateHostname(h string) error {
	if h == "" {
		return errors.New("must not be empty")
	}
	if len(h) > 253 {
		return errors.New("longer than 253 characters")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New("must be a full name such as www.example.com")
	}
	for _, l := range labels {
		if l == "" {
			return errors.New("empty label (two dots in a row, or a dot at the start or end)")
		}
		if len(l) > 63 {
			return errors.New("a label is longer than 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("a label starts or ends with '-'")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("character %q is not allowed; use lower-case a-z, 0-9 and '-' (xn-- form for other scripts)", rune(c))
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return errors.New("IP addresses are not hostnames")
	}
	return nil
}

// ----- Static root syntax (S-11, S-13) -----

// ValidateRootSyntax checks the form of a static root without touching the
// disk: an absolute, cleaned path on a lettered drive, with no network or
// device prefix, no Windows path tricks and no blocked folder name.
// internal/sitecheck resolves the real folder and checks it again.
func ValidateRootSyntax(root string) error {
	if root == "" {
		return errors.New("must not be empty")
	}
	if len(root) > 1024 {
		return errors.New("longer than 1024 characters")
	}
	if !utf8.ValidString(root) {
		return errors.New("not valid text")
	}
	if strings.HasPrefix(root, `\\`) || strings.HasPrefix(root, `//`) {
		return errors.New("network and device paths are not supported; choose a folder on a local drive")
	}
	if len(root) < 3 || !isDriveLetter(root[0]) || root[1] != ':' || root[2] != '\\' {
		return errors.New(`must be a full path such as C:\Sites\blog`)
	}
	if filepath.Clean(root) != root {
		return errors.New(`must be in canonical form (no "..", "." or repeated separators, no trailing separator)`)
	}
	rest := root[3:]
	if rest == "" {
		return errors.New("a whole drive cannot be published")
	}
	first, _, _ := strings.Cut(rest, `\`)
	if slices.Contains(systemRootFolders, strings.ToLower(first)) {
		return fmt.Errorf("%s is a Windows system folder and cannot be published", first)
	}
	for comp := range strings.SplitSeq(rest, `\`) {
		if err := checkPathComponent(comp); err != nil {
			return err
		}
		lc := strings.ToLower(comp)
		if lc == "appdata" || lc == ".ssh" {
			return fmt.Errorf("folders inside %s cannot be published", comp)
		}
	}
	return nil
}

// systemRootFolders are folders Windows keeps at the top of a drive that hold
// other users' deleted files, restore points, upgrade leftovers or recovery
// images (lower case).
var systemRootFolders = []string{
	"$recycle.bin", "system volume information", "windows.old", "recovery", "config.msi",
	"$windows.~bt", "$windows.~ws", "$winreagent", "$sysreset", "msocache", "programdata",
}

func isDriveLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// checkPathComponent rejects the Windows file name forms that can alias or
// hide another file: reserved characters (including ':' for alternate data
// streams), control characters, trailing dots or spaces, reserved device
// names and 8.3 short names.
func checkPathComponent(c string) error {
	if c == "" || c == "." || c == ".." {
		return errors.New("empty, '.' or '..' path component")
	}
	for _, r := range c {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"/\|?*`, r) {
			return fmt.Errorf("character %q is not allowed in a folder name", r)
		}
	}
	if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
		return errors.New("folder names ending in a dot or space are not allowed")
	}
	if IsReservedDeviceName(c) {
		return fmt.Errorf("%q is a reserved Windows device name", c)
	}
	if HasShortNameMarker(c) {
		return errors.New("8.3 short names (such as PROGRA~1) are not allowed; use the full name")
	}
	return nil
}

var reservedNames = []string{
	"con", "prn", "aux", "nul", "conin$", "conout$", "clock$",
	"com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "com¹", "com²", "com³",
	"lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt¹", "lpt²", "lpt³",
}

// IsReservedDeviceName reports whether a file name component names a Windows
// device (CON, NUL, COM1 ...), with or without an extension and with any
// trailing spaces before the extension.
func IsReservedDeviceName(c string) bool {
	base, _, _ := strings.Cut(c, ".")
	base = strings.TrimRight(base, " ")
	base = strings.ToLower(base)
	return slices.Contains(reservedNames, base)
}

// HasShortNameMarker reports whether a component contains '~' followed by a
// digit, the mark of an 8.3 short name such as SECRET~1.TXT. This also
// refuses some legitimate long names; that is the price of never letting a
// short name alias a hidden or blocked file.
func HasShortNameMarker(c string) bool {
	for i := 0; i+1 < len(c); i++ {
		if c[i] == '~' && c[i+1] >= '0' && c[i+1] <= '9' {
			return true
		}
	}
	return false
}

// ----- Response headers (S-16) -----

var defaultHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",
	"Referrer-Policy":         "strict-origin-when-cross-origin",
	"Content-Security-Policy": "frame-ancestors 'none'",
	"Permissions-Policy":      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}

// ManagedHeaders lists the security headers that are sent by default and can
// be changed per site, sorted.
func ManagedHeaders() []string {
	names := make([]string, 0, len(defaultHeaders))
	for k := range defaultHeaders {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

// DefaultHeaders returns a copy of the default security headers.
func DefaultHeaders() map[string]string {
	m := make(map[string]string, len(defaultHeaders))
	for k, v := range defaultHeaders {
		m[k] = v
	}
	return m
}

// EffectiveHeaders returns the security headers a site sends: the defaults
// with the site's overrides applied. Headers overridden with "" are left out.
func (s Site) EffectiveHeaders() map[string]string {
	m := DefaultHeaders()
	for k, v := range s.ResponseHeaders {
		if _, ok := m[k]; !ok {
			continue
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func validHeaderValue(v string) error {
	if len(v) > maxHeaderValueLen {
		return fmt.Errorf("longer than %d characters", maxHeaderValueLen)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return errors.New("only printable ASCII is allowed in a header value")
		}
	}
	if strings.TrimSpace(v) != v {
		return errors.New("must not start or end with a space")
	}
	// Caddy expands {placeholders} in header values on every response, and
	// {file.PATH} or {env.NAME} would publish files and environment variables
	// to every visitor (DR-2). No header these values set needs a brace.
	if strings.ContainsAny(v, "{}") {
		return errors.New("must not contain { or }")
	}
	return nil
}

// ----- Display text -----

// checkPrintable refuses invalid UTF-8, control characters and the Unicode
// bidirectional controls that can make a name display differently from what
// it is.
func checkPrintable(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("not valid text")
	}
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) {
			return fmt.Errorf("character %U is not allowed", r)
		}
	}
	return nil
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}
