package supervisor

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/accesslog"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// firewallMatchWindow is how far apart in time an access-log entry and a
// firewall event may be and still describe the same request.
const firewallMatchWindow = 5 * time.Second

// siteHosts maps every hostname of cfg's sites, and every quick share
// hostname, to its site id.
func (s *Supervisor) siteHosts(cfg config.Config) map[string]string {
	m := map[string]string{}
	for _, site := range cfg.Sites {
		for _, h := range site.Hostnames {
			m[h] = site.ID
		}
	}
	for id, h := range s.quickHosts() {
		m[h] = id
	}
	return m
}

// accessList answers access.list (S-31): the parameters are checked here,
// and the logs are read only from the web worker's own log folder. Each
// entry is matched to the firewall event for the same request, if any, so
// Activity can say which rule blocked it.
func (s *Supervisor) accessList(p *ipc.AccessListParams) (any, *ipc.Error) {
	if p.SiteID != "" && !config.ValidSiteID(p.SiteID) {
		return nil, ipc.Errorf(ipc.CodeInvalid, "That is not a valid site id.")
	}
	if !accesslog.ValidClass(p.Class) {
		return nil, ipc.Errorf(ipc.CodeInvalid, "That is not a valid result filter.")
	}
	if p.Limit < 0 || p.Limit > ipc.MaxAccessPage {
		return nil, ipc.Errorf(ipc.CodeInvalid, "The page size must be between 1 and %d.", ipc.MaxAccessPage)
	}
	rec, err := s.current()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read.")
	}
	hosts := s.siteHosts(rec.Config)
	q := accesslog.Query{Class: p.Class, After: p.After, Before: p.Before, Limit: p.Limit}
	if p.SiteID != "" {
		q.Hosts = map[string]bool{}
		for h, id := range hosts {
			if id == p.SiteID {
				q.Hosts[h] = true
			}
		}
	}
	page, err := accesslog.Read(s.opts.Paths.WebLogs(), q)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The access log could not be read.")
	}
	res := ipc.AccessListResult{Entries: make([]ipc.AccessEntry, 0, len(page.Entries)), Skipped: page.Skipped, More: page.More}
	events := s.firewallEventsAround(page.Entries)
	for _, e := range page.Entries {
		ae := ipc.AccessEntry{Entry: e, SiteID: hosts[e.Host]}
		if ev, ok := matchEvent(events, e); ok {
			ae.Firewall = &ipc.FirewallMatch{Action: ev.Action, Rules: ev.Rules}
		}
		if p.Class == accesslog.ClassBlocked && (ae.Firewall == nil || ae.Firewall.Action != fwevent.ActionBlocked) {
			continue
		}
		res.Entries = append(res.Entries, ae)
	}
	return res, nil
}

// firewallEventsAround reads the firewall events in the time span of
// entries. A firewall log that cannot be read leaves the entries without
// matches rather than failing the whole page.
func (s *Supervisor) firewallEventsAround(entries []accesslog.Entry) []fwevent.Event {
	if len(entries) == 0 {
		return nil
	}
	newest, oldest := entries[0].Time, entries[len(entries)-1].Time
	page, err := fwevent.Read(s.opts.Paths.WebLogs(), fwevent.Query{Before: newest.Add(firewallMatchWindow), Limit: fwevent.MaxPage})
	if err != nil {
		return nil
	}
	out := page.Events[:0]
	for _, ev := range page.Events {
		if !ev.Time.Before(oldest.Add(-firewallMatchWindow)) {
			out = append(out, ev)
		}
	}
	return out
}

// matchEvent finds the firewall event for the same request as e: same host,
// path, client address and method, within firewallMatchWindow.
func matchEvent(events []fwevent.Event, e accesslog.Entry) (fwevent.Event, bool) {
	for _, ev := range events {
		if ev.Host != e.Host || ev.URI != e.URI || ev.ClientIP != e.ClientIP || ev.Method != e.Method {
			continue
		}
		d := ev.Time.Sub(e.Time)
		if d < 0 {
			d = -d
		}
		if d <= firewallMatchWindow {
			if ev.Action == fwevent.ActionBlocked && e.Status != 403 {
				continue
			}
			return ev, true
		}
	}
	return fwevent.Event{}, false
}

// configExport returns the settings to save. They never hold a secret
// (S-40); the control panel writes the file the user chooses.
func (s *Supervisor) configExport() (any, *ipc.Error) {
	rec, err := s.current()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read.")
	}
	return ipc.ConfigExportResult{Revision: rec.Revision, Config: rec.Config}, nil
}

// configImport replaces the settings with an imported copy (S-32: always a
// weakening action, confirmed with a token that names what changes). Every
// static folder is resolved and checked as site.put does. An imported static
// site comes in switched off unless the same folder is live now: turning it
// on runs the exposure check (ADR-0008). Quick shares and the tunnel
// settings stay as they are.
func (s *Supervisor) configImport(c winsec.Caller, p *ipc.ConfigImportParams) (any, *ipc.Error) {
	next := p.Config
	next.MigrateLegacy()
	next.Normalize()
	if err := next.Validate(); err != nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "The imported settings are not valid: %v", err)
	}
	for i := range next.Sites {
		site := &next.Sites[i]
		site.QuickShare = nil
		if site.Type != config.TypeStatic || site.Static == nil {
			continue
		}
		canon, err := s.opts.CheckRoot(filepath.Clean(site.Static.Root))
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, ipc.Errorf(ipc.CodeInvalid, "SoiréeHost cannot open the folder of site %q. Add that site from the control panel instead, which gives SoiréeHost access to its folder.", site.ID)
		}
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInvalid, "The folder of site %q cannot be published: %v", site.ID, err)
		}
		if s.opts.WorkerCanRead != nil {
			ok, err := s.opts.WorkerCanRead(canon)
			if err != nil || !ok {
				return nil, ipc.Errorf(ipc.CodeInvalid, "The web server may not read the folder of site %q (%s). Add that site from the control panel instead.", site.ID, canon)
			}
		}
		site.Static.Root = canon
	}
	detail := map[string]string{"sites": strconv.Itoa(len(next.Sites))}
	var switchedOff []string
	res, e := s.change(c, "config.import", detail, func(cfg *config.Config) *ipc.Error {
		imported := next
		imported.Sites = slices.Clone(next.Sites)
		imported.Tunnel = cfg.Tunnel
		switchedOff = switchedOff[:0]
		for i := range imported.Sites {
			site := &imported.Sites[i]
			j := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == site.ID })
			if j >= 0 {
				site.QuickShare = cfg.Sites[j].QuickShare
			}
			if site.Enabled && site.Type == config.TypeStatic && site.Static != nil {
				live := j >= 0 && cfg.Sites[j].Enabled && cfg.Sites[j].Static != nil &&
					cfg.Sites[j].Static.Root == site.Static.Root && cfg.Sites[j].AllowWellKnown == site.AllowWellKnown
				if !live {
					site.Enabled = false
					switchedOff = append(switchedOff, site.ID)
				}
			}
		}
		var w weakenings
		w.add("import", fmt.Sprintf("Importing replaces all your settings: %d site(s) now, %d after the import.", len(cfg.Sites), len(imported.Sites)))
		if added := newLANTargets(*cfg, imported); len(added) > 0 {
			w.add("allow_lan", fmt.Sprintf("The imported settings forward to devices on your local network (%s), which makes them reachable from the internet.", strings.Join(added, ", ")))
		}
		w.firewall(*cfg, imported)
		w.updates(*cfg, imported)
		w.headers(*cfg, imported)
		q := *p
		q.Confirmation = ""
		if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodConfigImport, params: q, token: p.Confirmation}, detail); e != nil {
			return e
		}
		*cfg = imported
		return nil
	})
	if e != nil {
		return s.withTunnel(nil, e)
	}
	if len(switchedOff) > 0 {
		if r, ok := res.(ipc.ConfigResult); ok {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%d static site(s) were imported switched off: %s. Turn each on to check its folder before it goes live.",
				len(switchedOff), strings.Join(switchedOff, ", ")))
			res = r
		}
	}
	return s.withTunnel(res, nil)
}
