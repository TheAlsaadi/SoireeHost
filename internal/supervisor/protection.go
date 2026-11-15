package supervisor

import (
	"errors"
	"fmt"
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

// check refuses the change unless it is confirmed; with confirmation it
// records the tags in the audit detail.
func (w *weakenings) check(confirm bool, detail map[string]string) *ipc.Error {
	if len(w.tags) == 0 {
		return nil
	}
	if !confirm {
		return ipc.Errorf(ipc.CodeConfirmationRequired, "%s Confirm to continue.", strings.Join(w.sentences, " "))
	}
	detail["weakening"] = strings.Join(w.tags, ",")
	return nil
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
		return nil, nil, ipc.Errorf(ipc.CodeInvalid, "The folder could not be checked before it goes live: %s", trimReason(err))
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
		warn = append(warn, "The folder is too large to check completely; the exposure report lists only what was checked.")
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
