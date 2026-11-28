package gui

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"rsc.io/qr"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// Local holds the control panel's own helpers, which never reach the
// supervisor: the folder grant, the port picker, the QR code, links,
// the clipboard and the sign-in entry. Like Control it takes nothing from
// the UI that reaches a command line, and the only path it accepts is a
// folder the user chose to publish, which it checks before changing it.
type Local struct {
	desktop desktop
}

// desktop is what Local needs from the window system, so tests can stand
// in for it.
type desktop interface {
	OpenURL(url string) error
	SetClipboard(text string) bool
	ChooseFolder() (string, error)
	SaveFile(name, text string) (bool, error)
	OpenTextFile(maxBytes int64) (string, error)
}

// NewLocal returns the helpers over a desktop.
func NewLocal(d desktop) *Local { return &Local{desktop: d} }

func plainError(code, msg string) error { return &ipc.Error{Code: code, Message: msg} }

// ChooseFolder asks the user for a folder to publish. An empty answer means
// the user cancelled.
func (l *Local) ChooseFolder() (string, error) { return l.desktop.ChooseFolder() }

// PrepareFolder checks a folder the user chose or dropped (S-11) and gives
// the web worker read access to it and the supervisor enough to check it
// (ADR-0006), through one handle that never follows a link (SE-07). It
// returns the folder's canonical path for the site's settings.
func (l *Local) PrepareFolder(path string) (string, error) {
	if path == "" || len(path) > 32767 {
		return "", plainError(ipc.CodeInvalid, "Choose a folder.")
	}
	loc, err := sitecheck.DefaultLocations()
	if err != nil {
		return "", plainError(ipc.CodeInternal, "Could not find the system folders to protect.")
	}
	canon, err := winsec.GrantSiteAccess(filepath.Clean(path),
		winsec.WebAccount(), winsec.SupervisorAccount(),
		func(p string) (string, error) { return sitecheck.CheckRoot(p, loc) })
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return "", plainError(ipc.CodeInvalid, "You are not allowed to change who can read that folder. Choose a folder you own, or copy the site into one.")
	}
	if err != nil {
		return "", plainError(ipc.CodeInvalid, fmt.Sprintf("That folder cannot be published: %v", err))
	}
	return canon, nil
}

// Port is a local port something listens on, for the port picker.
type Port struct {
	Port    uint16 `json:"port"`
	Process string `json:"process"`
	// Loopback is true when the app can be reached on this PC's own
	// address, which a proxy site needs (S-10).
	Loopback bool `json:"loopback"`
	// IPv4 and IPv6 say which loopback address answers: 127.0.0.1, ::1 or
	// both. Many development servers listen on ::1 only, and a proxy site
	// must then forward to [::1].
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
}

// ListeningPorts lists the TCP ports apps listen on, from 1024 up, with the
// process name where Windows lets this user read it ("3000 (node.exe)").
// SoiréeHost's own ports are left out.
func (l *Local) ListeningPorts() ([]Port, error) {
	eps, err := winsec.TCPListeners()
	if err != nil {
		return nil, plainError(ipc.CodeUnavailable, "Could not read which ports are in use.")
	}
	own := ownPIDs()
	byPort := map[uint16]*Port{}
	for _, ep := range eps {
		p := ep.Addr.Port()
		if p < 1024 || own[ep.PID] || ep.PID == 0 || ep.PID == 4 {
			continue
		}
		a := ep.Addr.Addr()
		loop := a.IsLoopback() || a == netip.IPv4Unspecified() || a == netip.IPv6Unspecified()
		cur, ok := byPort[p]
		if !ok {
			cur = &Port{Port: p, Process: processName(ep.PID)}
			byPort[p] = cur
		}
		cur.Loopback = cur.Loopback || loop
		if loop {
			if a.Is4() {
				cur.IPv4 = true
			} else {
				cur.IPv6 = true
			}
		}
	}
	out := make([]Port, 0, len(byPort))
	for _, p := range byPort {
		if ownPort(*p) {
			continue
		}
		out = append(out, *p)
	}
	slices.SortFunc(out, func(a, b Port) int { return int(a.Port) - int(b.Port) })
	return out, nil
}

// ownPort reports whether a port is SoiréeHost's own: held by its programs,
// or, when the owner's name cannot be read (the services run under their
// own accounts), in one of the ranges it uses. A proxy site may never point
// at one (S-10).
func ownPort(p Port) bool {
	if strings.EqualFold(p.Process, "soireehost.exe") || strings.EqualFold(p.Process, "cloudflared.exe") {
		return true
	}
	if p.Process != "" {
		return false
	}
	n := int(p.Port)
	return n == 8787 || (n >= config.QuickSharePortMin && n <= config.QuickSharePortMax) ||
		(n >= config.DefaultMetricsPort && n <= config.QuickShareMetricsMax)
}

// ownPIDs is this process, whose ports are never offered.
func ownPIDs() map[uint32]bool { return map[uint32]bool{uint32(os.Getpid()): true} } // #nosec G115 -- a Windows process id fits in 32 bits

// processName returns the image name of a process, or "" if this user may
// not read it.
func processName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(windows.MAX_LONG_PATH)
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:n]))
}

// QRCode is a QR code as rows of dark (true) and light modules.
type QRCode struct {
	Size    int      `json:"size"`
	Modules [][]bool `json:"modules"`
}

// maxQRText bounds what is encoded; a quick share address is far shorter.
const maxQRText = 256

// QRCode encodes an https address as a QR code, made on this PC (plan
// section 6): nothing is sent anywhere. The UI draws it as SVG rectangles.
func (l *Local) QRCode(text string) (QRCode, error) {
	if len(text) > maxQRText || !strings.HasPrefix(text, "https://") {
		return QRCode{}, plainError(ipc.CodeInvalid, "Only a site address can be shown as a QR code.")
	}
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return QRCode{}, plainError(ipc.CodeInternal, "Could not make the QR code.")
	}
	out := QRCode{Size: c.Size, Modules: make([][]bool, c.Size)}
	for y := range c.Size {
		out.Modules[y] = make([]bool, c.Size)
		for x := range c.Size {
			out.Modules[y][x] = c.Black(x, y)
		}
	}
	return out, nil
}

// knownLinks are the only pages the control panel opens, in the user's own
// browser. The UI names one; it never passes an address (S-33).
//
// #nosec G101 -- public documentation addresses; "token" is part of a page name
var knownLinks = map[string]string{
	"cloudflare-dashboard": "https://one.dash.cloudflare.com/",
	"tunnel-token-help":    "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/",
	"project":              "https://github.com/TheAlsaadi/SoireeHost",
	"security-policy":      "https://github.com/TheAlsaadi/SoireeHost/security/policy",
}

// OpenKnownLink opens one of the known pages in the default browser.
func (l *Local) OpenKnownLink(name string) error {
	u, ok := knownLinks[name]
	if !ok {
		return plainError(ipc.CodeInvalid, "Unknown link.")
	}
	return l.desktop.OpenURL(u)
}

// OpenSiteAddress opens a site's own address in the default browser. Only
// an https address made of a valid hostname is opened.
func (l *Local) OpenSiteAddress(address string) error {
	host, ok := strings.CutPrefix(address, "https://")
	host = strings.TrimSuffix(host, "/")
	if !ok || config.ValidateHostname(host) != nil {
		return plainError(ipc.CodeInvalid, "That is not a site address.")
	}
	return l.desktop.OpenURL("https://" + host + "/")
}

// CopyText puts text on the clipboard.
func (l *Local) CopyText(text string) bool { return l.desktop.SetClipboard(text) }

// SaveExport asks where to save exported settings and writes them there. It
// reports false if the user cancelled.
func (l *Local) SaveExport(text string) (bool, error) {
	return l.desktop.SaveFile("soireehost-settings.json", text)
}

// OpenImport asks the user for an exported settings file and returns its
// text, at most config.MaxConfigBytes. An empty answer means cancelled.
func (l *Local) OpenImport() (string, error) { return l.desktop.OpenTextFile(config.MaxConfigBytes) }

// Start at sign-in (owner decision of 15 Nov 2026): a per-user Run entry,
// no administrator rights, only ever for the user running the control panel.
const (
	runKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue = "SoireeHost"
)

// errNotInstalled refuses the sign-in entry for a copy that is not the
// installed one, so the entry never points at a file in Downloads.
var errNotInstalled = &ipc.Error{Code: ipc.CodeUnavailable, Message: "Starting at sign-in is available once SoiréeHost is installed."}

// installedExe returns the running program's path if it is the installed
// copy under Program Files.
func installedExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", errNotInstalled
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" || !strings.EqualFold(filepath.Dir(exe), filepath.Join(pf, "SoireeHost")) {
		return "", errNotInstalled
	}
	return exe, nil
}

// StartAtSignIn reports whether the sign-in entry is set.
func (l *Local) StartAtSignIn() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, nil
	}
	defer k.Close() //nolint:errcheck // read-only
	_, _, err = k.GetStringValue(runValue)
	return err == nil, nil
}

// SetStartAtSignIn writes or removes the sign-in entry.
func (l *Local) SetStartAtSignIn(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return plainError(ipc.CodeUnavailable, "Could not change the sign-in setting.")
	}
	defer k.Close() //nolint:errcheck // closed after the write
	if !on {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return plainError(ipc.CodeUnavailable, "Could not change the sign-in setting.")
		}
		return nil
	}
	exe, err := installedExe()
	if err != nil {
		return err
	}
	if err := k.SetStringValue(runValue, `"`+exe+`" gui --tray`); err != nil {
		return plainError(ipc.CodeUnavailable, "Could not change the sign-in setting.")
	}
	return nil
}
