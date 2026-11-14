package supervisor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// tunnelRefusedReason replaces whatever text the tunnel launcher gives when
// it refuses a plan: no worker text from the tunnel side ever reaches a
// caller, a status or a log, so nothing can echo the token (R-21).
const tunnelRefusedReason = "the tunnel launcher refused the tunnel settings"

// tunnelState is what the supervisor knows about the tunnels at run time.
// Nothing here is saved: quick share hostnames change at every cloudflared
// start (ADR-0007).
type tunnelState struct {
	report ipc.TunnelReport
	hosts  map[string]string // site id -> quick share hostname
	note   string            // a problem the supervisor itself found
}

// tunnelPlan is the whole desired tunnel state for cfg (ADR-0007 section 9):
// the token tunnel if a token is given, and a quick share for every enabled
// site that is shared.
func tunnelPlan(cfg config.Config, token string) ipc.TunnelPlan {
	listen, _ := config.ParseListen(cfg.Listen)
	p := ipc.TunnelPlan{
		Offline:     cfg.Tunnel.Offline,
		Token:       token,
		ListenPort:  int(listen.Port()),
		MetricsPort: cfg.Tunnel.MetricsPort,
		Shares:      []ipc.SharePlan{},
	}
	for _, s := range cfg.Sites {
		if s.Enabled && s.QuickShare != nil {
			p.Shares = append(p.Shares, ipc.SharePlan{SiteID: s.ID, Port: s.QuickShare.Port, MetricsPort: s.QuickShare.MetricsPort})
		}
	}
	return p
}

// pushTunnel sends the current plan to the tunnel launcher and waits for its
// answer. Every tunnel change goes through here under tunnelMu, and each
// plan is the whole state, so the last push always wins (review finding
// GO-6). Lock order: changeMu, then tunnelMu.
func (s *Supervisor) pushTunnel() error {
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()
	return s.pushTunnelLocked()
}

func (s *Supervisor) pushTunnelLocked() error {
	rec, err := s.current()
	if err != nil {
		return err
	}
	token, note := "", ""
	st, err := s.secrets.Status(secrets.TunnelToken)
	if err != nil {
		note = "The tunnel token could not be read, so the tunnel is not running. Set the token again."
	} else if st.Set {
		tok, err := s.secrets.Get(secrets.TunnelToken)
		switch {
		case err != nil:
			note = "The tunnel token could not be read, so the tunnel is not running. Set the token again."
		default:
			if _, verr := config.ValidateTunnelToken(string(tok)); verr == nil {
				token = string(tok)
			} else {
				// a value stored before the format check existed (S-50)
				note = "The stored tunnel token is not a Cloudflare Tunnel token, so the tunnel is not running. Set the token again."
			}
			clear(tok)
		}
	}
	s.tmu.Lock()
	s.tstate.note = note
	s.tmu.Unlock()
	plan := tunnelPlan(rec.Config, token)
	return s.tunnel.load(ipc.WorkerMsg{Type: ipc.MsgLoad, Tunnel: &plan})
}

// withTunnel pushes the tunnel plan after a config change (whether it was
// applied or restored) and adds a warning to a successful result if the
// launcher did not take it.
func (s *Supervisor) withTunnel(res any, e *ipc.Error) (any, *ipc.Error) {
	err := s.pushTunnel()
	if e != nil || err == nil || errors.Is(err, errWorkerDown) {
		return res, e
	}
	if cr, ok := res.(ipc.ConfigResult); ok {
		cr.Warnings = append(cr.Warnings, "Saved, but the tunnel did not take the change: "+tunnelErrText(err))
		return cr, nil
	}
	return res, e
}

func tunnelErrText(err error) string {
	var le *loadError
	if errors.As(err, &le) {
		return le.reason
	}
	return tunnelRefusedReason
}

// tunnelReport takes the launcher's latest report. If a quick share's
// hostname changed, the web worker is reloaded so that share's port serves
// the new hostname and nothing else (S-06).
func (s *Supervisor) tunnelReport(r ipc.TunnelReport) {
	hosts := map[string]string{}
	for _, t := range r.Tunnels {
		if t.Kind == ipc.TunnelKindQuick && config.ValidQuickShareHostname(t.Hostname) {
			hosts[t.SiteID] = t.Hostname
		}
	}
	s.tmu.Lock()
	s.tstate.report = r
	changed := !maps.Equal(hosts, s.tstate.hosts)
	s.tstate.hosts = hosts
	s.tmu.Unlock()
	if changed {
		go s.reloadWeb()
	}
}

// tunnelGone forgets the tunnels when the launcher goes away: every
// cloudflared ends with it.
func (s *Supervisor) tunnelGone() {
	s.tmu.Lock()
	had := len(s.tstate.hosts) > 0
	s.tstate.report = ipc.TunnelReport{}
	s.tstate.hosts = nil
	s.tmu.Unlock()
	if had {
		go s.reloadWeb()
	}
}

// quickHosts is a copy of the quick share hostnames.
func (s *Supervisor) quickHosts() map[string]string {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return maps.Clone(s.tstate.hosts)
}

// reloadWeb loads the current config into the web worker again, with the
// current quick share hostnames.
func (s *Supervisor) reloadWeb() {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	rec, err := s.current()
	if err != nil {
		return
	}
	if err := s.applyWeb(rec); err != nil && !errors.Is(err, errWorkerDown) {
		s.web.setState(StateRunning, "The web server did not take the new quick share address: "+err.Error())
	}
}

// Sentences for the launcher's problem codes (S-34: plain text).
var problemText = map[string]string{
	ipc.ProblemBinaryMissing:      "The tunnel program is missing or was changed. Run Repair to restore it.",
	ipc.ProblemBinaryMismatch:     "The tunnel program is missing or was changed. Run Repair to restore it.",
	ipc.ProblemUnexpectedListener: "cloudflared opened a network socket SoiréeHost does not allow, so it was stopped.",
	ipc.ProblemStartFailed:        "cloudflared could not be started. The tunnel log has the details.",
	ipc.ProblemExited:             "cloudflared stopped unexpectedly and is being restarted.",
	ipc.ProblemIngressOutside:     "Your Cloudflare dashboard sends some traffic to a service other than SoiréeHost, so SoiréeHost's protections do not cover it. Point every public hostname at the service address shown here.",
}

// tunnelStatus is the tunnel part of status.get.
func (s *Supervisor) tunnelStatus(cfg config.Config) ipc.TunnelStatus {
	st := ipc.TunnelStatus{Offline: cfg.Tunnel.Offline, ServiceURL: "http://" + cfg.Listen, Tunnels: []ipc.TunnelView{}}
	if sec, err := s.secrets.Status(secrets.TunnelToken); err == nil {
		st.TokenSet = sec.Set
	}
	s.tmu.Lock()
	r, note := s.tstate.report, s.tstate.note
	s.tmu.Unlock()
	for _, t := range r.Tunnels {
		v := ipc.TunnelView{Kind: t.Kind, SiteID: t.SiteID, State: t.State, Connections: t.Connections, Since: t.Since}
		prefix := "Tunnel: "
		if t.Kind == ipc.TunnelKindQuick {
			v.Temporary, v.Label = true, ipc.QuickShareLabel
			if t.Hostname != "" {
				v.URL = "https://" + t.Hostname
			}
			prefix = fmt.Sprintf("Quick share for %s: ", t.SiteID)
		}
		for _, p := range t.Problems {
			if p == ipc.ProblemBinaryMissing || p == ipc.ProblemBinaryMismatch {
				st.RepairNeeded = true
			}
			if text, ok := problemText[p]; ok && !slices.Contains(st.Warnings, prefix+text) {
				st.Warnings = append(st.Warnings, prefix+text)
			}
		}
		st.Tunnels = append(st.Tunnels, v)
	}
	if note != "" {
		st.Warnings = append(st.Warnings, note)
	}
	return st
}

// quickShareStart shares an enabled site through a temporary link (S-51).
func (s *Supervisor) quickShareStart(c winsec.Caller, id string) (any, *ipc.Error) {
	if cur, err := s.current(); err == nil {
		for _, site := range cur.Config.Sites {
			if site.ID == id && site.QuickShare != nil {
				return ipc.ConfigResult{Revision: cur.Revision, Config: cur.Config, Warnings: cur.Config.Warnings()}, nil
			}
		}
	}
	detail := map[string]string{"site": id}
	return s.withTunnel(s.change(c, "quickshare.start", detail, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		if !cfg.Sites[i].Enabled {
			return ipc.Errorf(ipc.CodeInvalid, "Turn the site on before sharing it.")
		}
		if cfg.Sites[i].QuickShare != nil {
			// a start that raced another keeps the ports already chosen, so
			// the link does not change
			return nil
		}
		shared := 0
		for _, x := range cfg.Sites {
			if x.QuickShare != nil {
				shared++
			}
		}
		if shared >= config.MaxQuickShares {
			return ipc.Errorf(ipc.CodeInvalid, "At most %d sites can be shared at once. Stop sharing another site first.", config.MaxQuickShares)
		}
		port, metrics := s.pickSharePorts(*cfg)
		if port == 0 || metrics == 0 {
			return ipc.Errorf(ipc.CodeUnavailable, "No free port was found for the quick share. Close a program that uses ports %d to %d and try again.",
				config.QuickSharePortMin, config.QuickSharePortMax)
		}
		cfg.Sites[i].QuickShare = &config.QuickShare{Port: port, MetricsPort: metrics}
		detail["port"] = strconv.Itoa(port)
		return nil
	}))
}

// quickShareStop ends a site's quick share.
func (s *Supervisor) quickShareStop(c winsec.Caller, id string) (any, *ipc.Error) {
	return s.withTunnel(s.change(c, "quickshare.stop", map[string]string{"site": id}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites[i].QuickShare = nil
		return nil
	}))
}

// setOffline is the offline switch: while it is on, no cloudflared runs.
func (s *Supervisor) setOffline(c winsec.Caller, offline bool) (any, *ipc.Error) {
	return s.withTunnel(s.change(c, "tunnel.set_offline", map[string]string{"offline": strconv.FormatBool(offline)}, func(cfg *config.Config) *ipc.Error {
		cfg.Tunnel.Offline = offline
		return nil
	}))
}

// pickSharePorts chooses the lowest free ports in the quick share ranges
// that the config does not already use for anything, a proxy target
// included (R-06), and that nothing else on this PC is listening on.
func (s *Supervisor) pickSharePorts(cfg config.Config) (port, metrics int) {
	used := map[int]bool{}
	for _, p := range cfg.OwnPorts() {
		used[int(p)] = true
	}
	for _, site := range cfg.Sites {
		if site.Proxy == nil {
			continue
		}
		if ap, err := config.ParseTarget(site.Proxy.Target, true); err == nil && ap.Addr().IsLoopback() {
			used[int(ap.Port())] = true
		}
	}
	pick := func(lo, hi int) int {
		for p := lo; p <= hi; p++ {
			if !used[p] && s.opts.PortFree(p) {
				used[p] = true
				return p
			}
		}
		return 0
	}
	return pick(config.QuickSharePortMin, config.QuickSharePortMax), pick(config.QuickShareMetricsMin, config.QuickShareMetricsMax)
}

// LoopbackPortFree reports whether nothing listens on 127.0.0.1:port, by
// binding it for a moment (loopback only, S-01).
func LoopbackPortFree(port int) bool {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
