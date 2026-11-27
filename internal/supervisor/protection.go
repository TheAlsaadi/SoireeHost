package supervisor

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
)

// scanWait bounds the wait for the web worker's exposure check: its own scan
// time limit and some slack.
const scanWait = sitecheck.DefaultScanTime + 15*time.Second

// maxNamedPaths is how many exposed files a confirmation message names.
const maxNamedPaths = 10

// weakenings collects the weakening actions of one change (S-32): each a
// sentence for the confirmation message and a tag for the audit entry.
type weakenings struct {
	sentences []string
	tags      []string
}

func (w *weakenings) add(tag, sentence string) {
	w.tags = append(w.tags, tag)
	w.sentences = append(w.sentences, sentence)
}

// quickShares adds a sentence for each quick share that next runs and cur
// does not: going back to a revision must not quietly put a temporary
// public link back up after the owner stopped it (S-32, owner's decision of
// 27 Nov 2026).
func (w *weakenings) quickShares(cur, next config.Config, rev uint64) {
	shared := func(s config.Site) bool { return s.Enabled && s.QuickShare != nil }
	var ids []string
	for _, s := range next.Sites {
		if !shared(s) {
			continue
		}
		i := slices.IndexFunc(cur.Sites, func(x config.Site) bool { return x.ID == s.ID })
		if i < 0 || !shared(cur.Sites[i]) {
			ids = append(ids, s.ID)
		}
	}
	if len(ids) > 0 {
		w.add("quick_share", fmt.Sprintf("Revision %d shares %s through a temporary public link again, which you had stopped.",
			rev, strings.Join(ids, ", ")))
	}
}

// online adds a sentence when next takes the tunnel back online from the
// offline switch. Switching it off by hand is the owner's own act
// (ADR-0007), but a rollback that does it on the side would put every site
// back on the internet unasked (sharp-edges finding SE7-1).
func (w *weakenings) online(cur, next config.Config, rev uint64) {
	if cur.Tunnel.Offline && !next.Tunnel.Offline {
		w.add("online", fmt.Sprintf("Revision %d turns the offline switch off, so your sites are on the internet again.", rev))
	}
}

// updates adds a sentence when next turns the update check off (ADR-0004;
// S-32): no security fix arrives while it is off.
func (w *weakenings) updates(cur, next config.Config) {
	if config.UpdatesWeakened(cur, next) {
		w.add("updates_off", "This turns the update check off, so SoiréeHost will not learn of security fixes.")
	}
}

// firewallWeakening adds a sentence for each site whose firewall next makes
// weaker than cur (S-14, S-32; Detect only counts, owner decision of 15 Nov
// 2026).
func (w *weakenings) firewall(cur, next config.Config) {
	ids := config.FirewallWeakenings(cur, next)
	if len(ids) == 0 {
		return
	}
	modes := map[string]string{}
	for _, s := range next.Sites {
		modes[s.ID] = s.Firewall.EffectiveMode()
	}
	var parts []string
	for _, id := range ids {
		what := "turns its firewall off"
		if modes[id] == config.FirewallDetect {
			what = "sets its firewall to Detect only, so attacks are logged but not blocked"
		}
		parts = append(parts, fmt.Sprintf("Site %q %s.", id, what))
	}
	w.add("firewall", strings.Join(parts, " "))
}

// headers adds a sentence for each site whose security headers next makes
// weaker than cur: a header removed, or set to a value recognised as weaker
// (S-16, S-32, review finding SE-28).
func (w *weakenings) headers(cur, next config.Config) {
	added := config.HeaderWeakenings(cur, next)
	if len(added) == 0 {
		return
	}
	ids := make([]string, 0, len(added))
	for id := range added {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("Site %q stops sending, or weakens, these security headers: %s.", id, strings.Join(added[id], ", ")))
	}
	w.add("headers", strings.Join(parts, " "))
}

// exposureCheck runs the exposure check on a static site that is about to go
// live (ADR-0008). A folder that cannot be checked is not put live: the
// call fails. Files that would be served and look like secrets are a
// weakening action; names the path rules never serve come back as warnings.
func (s *Supervisor) exposureCheck(site config.Site, w *weakenings, detail map[string]string) (*sitecheck.ExposureReport, []string, *ipc.Error) {
	if site.Type != config.TypeStatic || site.Static == nil || !site.Enabled {
		return nil, nil, nil
	}
	m, err := s.web.scan(ipc.ScanRequest{Root: site.Static.Root, AllowWellKnown: site.AllowWellKnown}, scanWait)
	switch {
	case errors.Is(err, errWorkerDown):
		return nil, nil, ipc.Errorf(ipc.CodeUnavailable,
			"The web server is not running, so the folder cannot be checked before it goes live. Try again when it is running, or save the site switched off.")
	case err != nil:
		e := ipc.Errorf(ipc.CodeInvalid, "The folder could not be checked before it goes live: %s.", trimReason(err))
		if le, ok := errors.AsType[*loadError](err); ok {
			e = le.withDetail(e)
		}
		return nil, nil, e
	}
	rep := m.Exposure
	var warn []string
	var blocked int
	for _, f := range rep.Findings {
		if !f.Served {
			blocked++
		}
	}
	if blocked > 0 {
		warn = append(warn, fmt.Sprintf("The folder holds %d file(s) or folder(s) that are never served, such as .env or private keys (listed in the exposure report). Consider moving them out of the site folder.", blocked))
	}
	if rep.Incomplete {
		// a folder that could not be checked completely may serve secrets
		// nobody was told about, so going live with it needs confirmation
		// (sharp-edges finding SE7-2)
		w.add("scan_incomplete", "The folder is too large to check completely, so files that look like secrets could be served without being listed here.")
	}
	if served := rep.Served(); len(served) > 0 {
		names := make([]string, 0, maxNamedPaths)
		for i, f := range served {
			if i == maxNamedPaths {
				names = append(names, fmt.Sprintf("and %d more", len(served)-maxNamedPaths))
				break
			}
			names = append(names, f.Path)
		}
		w.add("exposed_files", fmt.Sprintf("The folder holds %d file(s) that look like secrets and would be served to anyone: %s.",
			len(served), strings.Join(names, ", ")))
		detail["exposed"] = strconv.Itoa(len(served))
	}
	return rep, warn, nil
}

// alreadyLive reports whether site is a static site that is already live
// with the same folder: it was checked, and any finding confirmed, when it
// went live, so editing its other settings does not check it again
// (pre-merge review, 15 Nov 2026).
func (s *Supervisor) alreadyLive(site config.Site) bool {
	cur, err := s.current()
	if err != nil || site.Static == nil {
		return false
	}
	for _, x := range cur.Config.Sites {
		if x.ID == site.ID && x.Enabled && x.Type == config.TypeStatic && x.Static != nil &&
			x.Static.Root == site.Static.Root && x.AllowWellKnown == site.AllowWellKnown {
			return true
		}
	}
	return false
}

// trimReason is the worker's reason without the wrapping prefix.
func trimReason(err error) string {
	return strings.TrimPrefix(err.Error(), errScanFailed.Error()+": ")
}

// firewallEvents answers firewall.events (S-31): the parameters are checked
// here, and the log is read only from the web worker's own log folder.
func (s *Supervisor) firewallEvents(p *ipc.FirewallEventsParams) (any, *ipc.Error) {
	if p.SiteID != "" && !config.ValidSiteID(p.SiteID) {
		return nil, ipc.Errorf(ipc.CodeInvalid, "That is not a valid site id.")
	}
	if p.Limit < 0 || p.Limit > ipc.MaxFirewallPage {
		return nil, ipc.Errorf(ipc.CodeInvalid, "The page size must be between 1 and %d.", ipc.MaxFirewallPage)
	}
	page, err := fwevent.Read(s.opts.Paths.WebLogs(), fwevent.Query{Site: p.SiteID, Before: p.Before, Limit: p.Limit})
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The firewall log could not be read.")
	}
	return ipc.FirewallEventsResult{Events: page.Events, Skipped: page.Skipped, More: page.More}, nil
}
