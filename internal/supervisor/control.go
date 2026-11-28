package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
	"github.com/TheAlsaadi/SoireeHost/internal/sitecheck"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

func (s *Supervisor) configGet() (any, *ipc.Error) {
	rec, err := s.current()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read: %v", err)
	}
	return ipc.ConfigResult{Revision: rec.Revision, Config: rec.Config, Warnings: rec.Config.Warnings()}, nil
}

func (s *Supervisor) configHistory() (any, *ipc.Error) {
	h, err := s.store.History()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The settings history could not be read: %v", err)
	}
	return ipc.HistoryResult{Revisions: h, LastGood: s.store.LastGood()}, nil
}

func (s *Supervisor) status() ipc.StatusResult {
	rec, _ := s.current()
	st := ipc.StatusResult{
		Version:   s.opts.Version,
		State:     StateRunning,
		Revision:  rec.Revision,
		Workers:   []ipc.WorkerStatus{s.web.status(), s.tunnel.status()},
		Warnings:  rec.Config.Warnings(),
		AuditOK:   s.auditOK(),
		StartedAt: s.started,
		Tunnel:    s.tunnelStatus(rec.Config),
		Update:    s.statusUpdate(),
	}
	if good := s.store.LastGood(); rec.Revision != 0 && good != rec.Revision {
		st.ConfigNote = fmt.Sprintf("Revision %d is saved but the web server last loaded revision %d.", rec.Revision, good)
	}
	return st
}

// change applies mutate to a copy of the current config, saves it, audits
// it, and loads it into the web worker. If the worker refuses it, the last
// revision the worker loaded is restored and the worker's reason returned
// (S-41).
func (s *Supervisor) change(c winsec.Caller, action audit.Action, detail map[string]string,
	mutate func(*config.Config) *ipc.Error,
) (any, *ipc.Error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	cur, err := s.current()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read: %v", err)
	}
	next, err := cloneConfig(cur.Config)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "Could not copy the settings.")
	}
	if e := mutate(&next); e != nil {
		return nil, e
	}
	rec, err := s.store.Save(next, c.SID, action.String())
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "%v", err)
	}
	detail["revision"] = strconv.FormatUint(rec.Revision, 10)
	if e := s.recordOrUndo(actorOf(c.SID), action, detail, cur.Config); e != nil {
		return nil, e
	}
	return s.applyOrRestore(rec, cur.Config)
}

// recordOrUndo audits a saved change. A weakening change stands only with its
// audit entry (S-32): when the entry cannot be written, prev is saved again
// before any worker has loaded the change, and the call fails. Other changes
// keep going; the failure shows on the Security page (audit_ok false).
func (s *Supervisor) recordOrUndo(actor audit.Actor, action audit.Action, detail map[string]string, prev config.Config) *ipc.Error {
	if s.record(actor, action, detail) == nil || detail["weakening"] == "" {
		return nil
	}
	back, err := s.store.Save(prev, winsec.SIDSystem, "Undid a weakening change that could not be audited")
	if err != nil {
		return ipc.Errorf(ipc.CodeInternal, "The audit log could not be written, and undoing the change failed: %v", err)
	}
	// best effort: the failed write may still have left the weakening's
	// entry in the log, so the undo is recorded too (security review SR-4)
	_ = s.record(audit.System, audit.ConfigUndone, map[string]string{"action": action.String(), "new_revision": strconv.FormatUint(back.Revision, 10)})
	return errNotAudited
}

// applyOrRestore loads rec into the web worker. If the worker refuses it, the
// last revision the worker loaded is restored and reloaded; if there is none
// yet, prev (the settings in force before this change) is saved again.
func (s *Supervisor) applyOrRestore(rec config.Record, prev config.Config) (any, *ipc.Error) {
	res := ipc.ConfigResult{Revision: rec.Revision, Config: rec.Config, Warnings: rec.Config.Warnings()}
	err := s.applyWeb(rec)
	var le *loadError
	switch {
	case err == nil:
		return res, nil
	case errors.Is(err, errWorkerDown):
		res.Warnings = append(res.Warnings, "Saved. The web server is not running right now, so the change applies when it starts.")
		return res, nil
	case errors.As(err, &le):
		good := s.store.LastGood()
		if good == rec.Revision {
			return nil, le.withDetail(ipc.Errorf(ipc.CodeInvalid, "The web server could not use these settings: %s.", le.reason))
		}
		var back config.Record
		rerr := errors.New("no revision the web server loaded is known")
		// the change may have been going offline or stopping a share: the
		// restore keeps whichever of the two is stricter (code review CR-1)
		safe := stricterTunnel(prev, rec.Config)
		if good != 0 {
			back, rerr = s.restoreGood(good, safe)
		}
		if rerr != nil {
			// the last good revision is unknown, cannot be read, or would
			// weaken the settings: restore the settings in force before this
			// change (R-22, SR-1)
			back, rerr = s.store.Save(safe, winsec.SIDSystem, "Restored the settings before a change the web server refused")
		}
		if rerr != nil {
			return nil, le.withDetail(ipc.Errorf(ipc.CodeInternal, "The web server could not use these settings (%s), and restoring revision %d failed: %v", le.reason, good, rerr))
		}
		_ = s.record(audit.System, audit.ConfigRestored, map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
			"restored_revision": strconv.FormatUint(good, 10), "new_revision": strconv.FormatUint(back.Revision, 10)})
		if aerr := s.applyWeb(back); aerr != nil && !errors.Is(aerr, errWorkerDown) {
			// review finding GO-4: saved is not loaded; say so
			return nil, le.withDetail(ipc.Errorf(ipc.CodeInvalid, "The web server could not use these settings, so the previous settings were saved again, but the web server has not loaded them yet (%v). Reason: %s.", aerr, le.reason))
		}
		return nil, le.withDetail(ipc.Errorf(ipc.CodeInvalid, "The web server could not use these settings, so the previous settings were restored. Reason: %s.", le.reason))
	default:
		return nil, ipc.Errorf(ipc.CodeUnavailable, "The change was saved but could not be applied: %v", err)
	}
}

// applyWeb builds the Caddy config for rec and loads it; on success the
// revision becomes the last good one.
func (s *Supervisor) applyWeb(rec config.Record) error {
	j, err := worker.BuildCaddyJSON(rec.Config, worker.Options{LogDir: s.opts.Paths.WebLogs(), QuickHosts: s.quickHosts()})
	if err != nil {
		return &loadError{reason: err.Error(), refused: true}
	}
	if err := s.web.load(ipc.WorkerMsg{Type: ipc.MsgLoad, Caddy: j}); err != nil {
		return err
	}
	return s.store.MarkGood(rec.Revision)
}

// restoreGood saves revision good again as the current settings after the
// web worker could not use newer ones. The tunnel side stays as it was in
// cur, the settings in force: the offline switch keeps its value, and no
// quick share comes back that is not running there (sharp-edges finding
// SE7-1). Neither decides whether the web worker can load the settings,
// and an automatic restore must never put anything back on the internet.
func (s *Supervisor) restoreGood(good uint64, cur config.Config) (config.Record, error) {
	old, err := s.store.Get(good)
	if err != nil {
		return config.Record{}, err
	}
	cfg, err := cloneConfig(old.Config)
	if err != nil {
		return config.Record{}, err
	}
	cfg.Tunnel.Offline = cur.Tunnel.Offline
	for i, site := range cfg.Sites {
		if site.QuickShare == nil {
			continue
		}
		j := slices.IndexFunc(cur.Sites, func(x config.Site) bool { return x.ID == site.ID })
		if j < 0 || !cur.Sites[j].Enabled || cur.Sites[j].QuickShare == nil {
			cfg.Sites[i].QuickShare = nil
		}
	}
	if restoreWeakens(cur, cfg) {
		return config.Record{}, errRestoreWeakens
	}
	return s.store.Save(cfg, winsec.SIDSystem, fmt.Sprintf("Rolled back to revision %d", good))
}

// stricterTunnel is prev with the tunnel side of both prev and next: offline
// if either is, and a quick share only where both run it.
func stricterTunnel(prev, next config.Config) config.Config {
	out, err := cloneConfig(prev)
	if err != nil {
		out = prev
		out.Sites = slices.Clone(prev.Sites)
	}
	out.Tunnel.Offline = prev.Tunnel.Offline || next.Tunnel.Offline
	for i, site := range out.Sites {
		if site.QuickShare == nil {
			continue
		}
		j := slices.IndexFunc(next.Sites, func(x config.Site) bool { return x.ID == site.ID })
		if j < 0 || !next.Sites[j].Enabled || next.Sites[j].QuickShare == nil {
			out.Sites[i].QuickShare = nil
		}
	}
	return out
}

// errRestoreWeakens refuses an automatic restore that would undo a
// tightening saved since the last good revision (security review SR-1).
var errRestoreWeakens = errors.New("it would put back settings weaker than the ones saved since (a site or hostname switched off, a folder, a device on your local network, a firewall, header or update setting)")

// restoreWeakens reports whether putting next in place of cur would expose
// more: a site, hostname or folder cur does not serve, .well-known turned
// on, or any change the S-32 weakening checks name. Nobody confirms an
// automatic restore, so it may only ever take things away.
func restoreWeakens(cur, next config.Config) bool {
	if len(newLANTargets(cur, next)) > 0 {
		return true
	}
	var w weakenings
	w.firewall(cur, next)
	w.updates(cur, next)
	w.headers(cur, next)
	if len(w.tags) > 0 {
		return true
	}
	for _, n := range next.Sites {
		if !n.Enabled {
			continue
		}
		i := slices.IndexFunc(cur.Sites, func(x config.Site) bool { return x.ID == n.ID })
		if i < 0 || !cur.Sites[i].Enabled {
			return true
		}
		c := cur.Sites[i]
		if n.Type != c.Type || n.AllowWellKnown && !c.AllowWellKnown {
			return true
		}
		if n.Static != nil && (c.Static == nil || !strings.EqualFold(n.Static.Root, c.Static.Root)) {
			return true
		}
		for _, h := range n.Hostnames {
			if !slices.Contains(c.Hostnames, h) {
				return true
			}
		}
	}
	return false
}

// workerConnected brings a newly connected worker up to date.
func (s *Supervisor) workerConnected(_ context.Context, role string) {
	switch role {
	case ipc.RoleWeb:
		s.changeMu.Lock()
		defer s.changeMu.Unlock()
		rec, err := s.current()
		if err != nil {
			s.web.setProblem("The saved settings could not be read: " + err.Error())
			return
		}
		err = s.applyWeb(rec)
		var le *loadError
		if !errors.As(err, &le) {
			if err == nil {
				s.connectLost.revision, s.connectLost.times = 0, 0
			}
			return
		}
		cause := "refused"
		if !le.refused {
			// S-41 (owner's decision of 27 Nov 2026): settings the worker
			// hangs on past the load timeout, or dies on at two connects in
			// a row, count as refused. One death may have another cause, so
			// the settings get one more start before they are blamed; a
			// hung worker never connects again, so a hang counts at once.
			if s.connectLost.revision != rec.Revision {
				s.connectLost.revision, s.connectLost.times = rec.Revision, 0
			}
			s.connectLost.times++
			cause = "stopped"
			if le.timedOut {
				cause = "timed_out"
			} else if s.connectLost.times < 2 {
				s.web.setProblem("The web server did not finish loading the saved settings: "+le.reason, le.detail)
				return
			}
		}
		// At connect time only a known-good revision is restored; with none,
		// the saved settings stay as they are and the reason is reported, so
		// a folder that is missing at boot never wipes the user's sites.
		s.web.setProblem("The web server could not use the saved settings: "+le.reason, le.detail)
		if good := s.store.LastGood(); good != 0 && good != rec.Revision {
			back, err := s.restoreGood(good, rec.Config)
			if err != nil {
				// reported, not hidden (R-22): the saved settings stay as
				// they are until someone fixes or replaces them
				s.web.setProblem(fmt.Sprintf("The web server could not use the saved settings (%s), and restoring revision %d failed: %v", le.reason, good, err), le.detail)
				_ = s.record(audit.System, audit.ConfigRestoreFailed, map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
					"restored_revision": strconv.FormatUint(good, 10)})
				return
			}
			_ = s.record(audit.System, audit.ConfigRestored, map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
				"restored_revision": strconv.FormatUint(good, 10), "new_revision": strconv.FormatUint(back.Revision, 10), "cause": cause})
			// a worker still stuck in the old load takes this one after it,
			// if ever; a restarted one loads the restored settings at connect
			if aerr := s.applyWeb(back); aerr != nil && !errors.Is(aerr, errWorkerDown) {
				// review finding GO-4: saved is not loaded; say so
				s.web.setProblem(fmt.Sprintf("The web server could not use the saved settings (%s). Revision %d was saved again, but the web server has not loaded it yet: %v", le.reason, good, aerr), le.detail)
			}
			// the launcher may still run a share or port of the failed
			// revision; it takes the restored plan (security review SR-3)
			_ = s.pushTunnel()
		}
	case ipc.RoleTunnel:
		// the whole tunnel plan, token included; the token travels only on
		// the tunnel pipe, which only the launcher's account can open (S-23)
		if err := s.pushTunnel(); err != nil && !errors.Is(err, errWorkerDown) {
			s.tunnel.setProblem("The tunnel launcher did not take the tunnel settings: " + tunnelErrText(err))
		}
	}
}

func (s *Supervisor) rollback(c winsec.Caller, p *ipc.RollbackParams) (any, *ipc.Error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	target, err := s.store.Get(p.Revision)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeNotFound, "%v", err)
	}
	// The settings in force now are what a refused rollback restores. If
	// they cannot be read, every LAN target counts as new.
	cur, cerr := s.current()
	detail := map[string]string{"to_revision": strconv.FormatUint(p.Revision, 10)}
	// S-32 (owner decision of 13 Nov 2026, review finding R-04): going back
	// to settings that forward to a device on the local network the current
	// ones do not needs the same confirmation as adding one, and is audited;
	// so does going back to a weaker firewall (ADR-0008)
	var w weakenings
	if added := newLANTargets(cur.Config, target.Config); len(added) > 0 {
		w.add("allow_lan", fmt.Sprintf("Revision %d forwards to a device on your local network (%s), which makes that device reachable from the internet.",
			p.Revision, strings.Join(added, ", ")))
	}
	w.firewall(cur.Config, target.Config)
	w.updates(cur.Config, target.Config)
	w.headers(cur.Config, target.Config)
	w.quickShares(cur.Config, target.Config, p.Revision)
	w.online(cur.Config, target.Config, p.Revision)
	// ADR-0008 decision 3: a static folder that goes live through a rollback
	// is checked as when it is switched on; a folder that cannot be checked
	// does not go live
	exposed := 0
	for _, site := range target.Config.Sites {
		if site.Type != config.TypeStatic || !site.Enabled || s.alreadyLive(site) {
			continue
		}
		d := map[string]string{}
		if _, _, perr := s.exposureCheck(site, &w, d); perr != nil {
			return nil, perr
		}
		n, _ := strconv.Atoi(d["exposed"])
		exposed += n
	}
	if exposed > 0 {
		detail["exposed"] = strconv.Itoa(exposed)
	}
	q := *p
	q.Confirmation = ""
	if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodConfigRollback, params: q, token: p.Confirmation}, detail); e != nil {
		return nil, e
	}
	rec, err := s.store.Rollback(p.Revision, c.SID)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeNotFound, "%v", err)
	}
	detail["revision"] = strconv.FormatUint(rec.Revision, 10)
	prev := cur.Config
	if cerr != nil {
		prev = config.Default()
	}
	if e := s.recordOrUndo(actorOf(c.SID), audit.ConfigRollback, detail, prev); e != nil {
		// the tunnel may have taken the rolled-back plan meanwhile; push
		// the undone one (security review SR-2)
		return s.withTunnel(nil, e)
	}
	return s.withTunnel(s.applyOrRestore(rec, prev))
}

// newLANTargets lists the local-network addresses next forwards to that cur
// does not.
func newLANTargets(cur, next config.Config) []string {
	have := map[string]bool{}
	for _, site := range cur.Sites {
		if site.Proxy != nil && site.Proxy.AllowLAN {
			have[site.Proxy.Target] = true
		}
	}
	var added []string
	for _, site := range next.Sites {
		if site.Proxy != nil && site.Proxy.AllowLAN && !have[site.Proxy.Target] {
			added = append(added, site.Proxy.Target)
			have[site.Proxy.Target] = true
		}
	}
	return added
}

func (s *Supervisor) sitePut(c winsec.Caller, p *ipc.SitePutParams) (any, *ipc.Error) {
	site := p.Site
	detail := map[string]string{"site": site.ID, "type": site.Type}
	if site.Type == config.TypeStatic && site.Static != nil {
		canon, err := s.opts.CheckRoot(filepath.Clean(site.Static.Root))
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, ipc.Errorf(ipc.CodeInvalid, "SoiréeHost cannot open that folder. Add the site from the control panel, which gives SoiréeHost access to the folder, or choose a folder outside your user profile.")
		}
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInvalid, "That folder cannot be published: %v", err)
		}
		if s.opts.WorkerCanRead != nil {
			ok, err := s.opts.WorkerCanRead(canon)
			if err != nil {
				// fail closed: a folder whose permissions cannot be read is
				// refused, not published unchecked (review finding R-07)
				return nil, ipc.Errorf(ipc.CodeInvalid, "Could not check whether the web server may read %s: %v", canon, err)
			}
			if !ok {
				return nil, ipc.Errorf(ipc.CodeInvalid, "The web server is not allowed to read %s. Add the site from the control panel, which grants read access, or give NT SERVICE\\%s read access to the folder.", canon, winsec.WebService)
			}
		}
		site.Static.Root = canon
		detail["root"] = canon
	}
	if site.Proxy != nil {
		detail["target"] = site.Proxy.Target
	}
	var w weakenings
	var rep *sitecheck.ExposureReport
	var warn []string
	if !s.alreadyLive(site) {
		var perr *ipc.Error
		if rep, warn, perr = s.exposureCheck(site, &w, detail); perr != nil {
			return nil, perr
		}
	}
	res, e := s.change(c, audit.SitePut, detail, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == site.ID })
		// quick shares are changed only through quickshare.start and
		// quickshare.stop; replacing a site keeps its share as it is
		site.QuickShare = nil
		if i >= 0 {
			site.QuickShare = cfg.Sites[i].QuickShare
		}
		// S-32: forwarding to a LAN device not already reachable through the
		// current settings is a weakening change, including pointing a site
		// that already allows the LAN at another device (review finding R-04)
		if len(newLANTargets(*cfg, config.Config{Sites: []config.Site{site}})) > 0 {
			w.add("allow_lan", "Forwarding to a device on your local network makes that device reachable from the internet through this site.")
		}
		// S-14, S-32: a weaker firewall than now, or a new site that starts
		// below Block, needs confirmation (ADR-0008)
		w.firewall(*cfg, config.Config{Sites: []config.Site{site}})
		w.headers(*cfg, config.Config{Sites: []config.Site{site}})
		q := *p
		q.Confirmation = ""
		if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodSitePut, params: q, token: p.Confirmation}, detail); e != nil {
			return e
		}
		if i >= 0 {
			cfg.Sites[i] = site
		} else {
			cfg.Sites = append(cfg.Sites, site)
		}
		return nil
	})
	return s.withTunnel(withExposure(res, e, rep, warn))
}

// withExposure adds the exposure check's report and warnings to a change's
// result.
func withExposure(res any, e *ipc.Error, rep *sitecheck.ExposureReport, warn []string) (any, *ipc.Error) {
	if e != nil {
		return nil, e
	}
	if r, ok := res.(ipc.ConfigResult); ok {
		r.Exposure = rep
		r.Warnings = append(r.Warnings, warn...)
		return r, nil
	}
	return res, nil
}

func (s *Supervisor) siteRemove(c winsec.Caller, id string) (any, *ipc.Error) {
	return s.withTunnel(s.change(c, audit.SiteRemove, map[string]string{"site": id}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites = slices.Delete(cfg.Sites, i, i+1)
		return nil
	}))
}

func (s *Supervisor) siteSetEnabled(c winsec.Caller, p *ipc.SiteEnabledParams) (any, *ipc.Error) {
	id, enabled := p.ID, p.Enabled
	detail := map[string]string{"site": id, "enabled": strconv.FormatBool(enabled)}
	// a static folder that goes live is checked first (ADR-0008)
	var w weakenings
	var rep *sitecheck.ExposureReport
	var warn []string
	var scanned string
	if enabled {
		cur, err := s.current()
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read: %v", err)
		}
		if i := slices.IndexFunc(cur.Config.Sites, func(x config.Site) bool { return x.ID == id }); i >= 0 {
			site := cur.Config.Sites[i]
			if !site.Enabled && site.Type == config.TypeStatic && site.Static != nil {
				site.Enabled = true
				var perr *ipc.Error
				if rep, warn, perr = s.exposureCheck(site, &w, detail); perr != nil {
					return nil, perr
				}
				scanned = site.Static.Root
			}
		}
	}
	res, e := s.change(c, audit.SiteSetEnabled, detail, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		site := cfg.Sites[i]
		if enabled && !site.Enabled && site.Type == config.TypeStatic && site.Static != nil && site.Static.Root != scanned {
			return ipc.Errorf(ipc.CodeUnavailable, "The site changed while its folder was being checked. Try again.")
		}
		q := *p
		q.Confirmation = ""
		if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodSiteSetEnabled, params: q, token: p.Confirmation}, detail); e != nil {
			return e
		}
		cfg.Sites[i].Enabled = enabled
		return nil
	})
	return s.withTunnel(withExposure(res, e, rep, warn))
}

// secretSet stores the tunnel token (write-only, S-35). Only a Cloudflare
// Tunnel token is accepted (S-50). Replacing a token that is already set
// changes the tunnel, so it needs confirmation (S-32). The whole call holds
// tunnelMu, from the "is one set?" check through storing and handing the
// token over, so two quick calls cannot both skip confirmation or leave the
// tunnel on the older token; a failed hand-over is reported (GO-6).
func (s *Supervisor) secretSet(c winsec.Caller, p *ipc.SecretSetParams) (any, *ipc.Error) {
	if p.Name != secrets.TunnelToken {
		return nil, ipc.Errorf(ipc.CodeInvalid, "Unknown secret %q.", p.Name)
	}
	if _, err := config.ValidateTunnelToken(p.Value); err != nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "%s.", capitalise(config.ErrNotTunnelToken.Error()))
	}
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()
	st, err := s.secrets.Status(p.Name)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The secrets could not be read.")
	}
	detail := map[string]string{"name": p.Name}
	if st.Set {
		var w weakenings
		w.add("tunnel", "A tunnel token is already set. Replacing it changes which tunnel your sites use.")
		q := *p
		q.Confirmation = ""
		if e := w.check(s.conf, confirmRequest{sid: c.SID, method: ipc.MethodSecretSet, params: q, token: p.Confirmation}, detail); e != nil {
			return nil, e
		}
	}
	action := audit.SecretSet
	if st.Set {
		action = audit.SecretReplace
		// replacing the token is a weakening action (S-32): the old token
		// cannot be put back, so the entry is written before the change and
		// a failure refuses it
		if s.record(actorOf(c.SID), action, detail) != nil {
			return nil, errNotAudited
		}
	}
	if err := s.secrets.Set(p.Name, []byte(p.Value)); err != nil {
		if st.Set {
			_ = s.record(actorOf(c.SID), audit.SecretReplaceFailed, map[string]string{"name": p.Name})
		}
		return nil, ipc.Errorf(ipc.CodeInvalid, "The token could not be stored: %v", err)
	}
	if !st.Set {
		_ = s.record(actorOf(c.SID), action, detail)
	}
	res := ipc.SecretStatusResult{}
	switch err := s.pushTunnelLocked(); {
	case err == nil:
	case errors.Is(err, errWorkerDown):
		res.Warnings = append(res.Warnings, "Saved. The tunnel launcher is not running right now, so the token is used when it starts.")
	default:
		res.Warnings = append(res.Warnings, "Saved, but the tunnel did not take the new token: "+tunnelErrText(err))
	}
	st, _ = s.secrets.Status(p.Name)
	res.Secrets = []ipc.SecretStatus{{Name: st.Name, Set: st.Set, SetAt: st.SetAt}}
	return res, nil
}

// capitalise upper-cases the first letter of an ASCII sentence.
func capitalise(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

func (s *Supervisor) auditList(p *ipc.AuditListParams) (any, *ipc.Error) {
	limit := p.Limit
	if limit <= 0 || limit > ipc.MaxAuditPage {
		limit = ipc.MaxAuditPage
	}
	path := filepath.Join(s.opts.Paths.Audit(), "audit.log")
	entries, err := audit.List(path, p.After, limit)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The audit log could not be read.")
	}
	rep, err := s.audit.Verify()
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInternal, "The audit log could not be checked.")
	}
	return ipc.AuditListResult{Entries: entries, Report: rep}, nil
}

func cloneConfig(c config.Config) (config.Config, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return config.Config{}, err
	}
	var out config.Config
	err = json.Unmarshal(b, &out)
	return out, err
}
