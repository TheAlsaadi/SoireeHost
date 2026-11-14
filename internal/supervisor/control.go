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
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
	"github.com/TheAlsaadi/SoireeHost/internal/worker"
)

// handle dispatches one control call. Everything that reaches it has been
// decoded strictly into the method's own type by ipc.DecodeRequest.
func (s *Supervisor) handle(_ context.Context, c winsec.Caller, method string, params any) (any, *ipc.Error) {
	switch method {
	case ipc.MethodStatus:
		return s.status(), nil
	case ipc.MethodConfigGet:
		rec, err := s.current()
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The saved settings could not be read: %v", err)
		}
		return ipc.ConfigResult{Revision: rec.Revision, Config: rec.Config, Warnings: rec.Config.Warnings()}, nil
	case ipc.MethodConfigHistory:
		h, err := s.store.History()
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The settings history could not be read: %v", err)
		}
		return ipc.HistoryResult{Revisions: h, LastGood: s.store.LastGood()}, nil
	case ipc.MethodConfigRollback:
		p, perr := paramsAs[ipc.RollbackParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.rollback(c, p)
	case ipc.MethodSitePut:
		p, perr := paramsAs[ipc.SitePutParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.sitePut(c, p)
	case ipc.MethodSiteRemove:
		p, perr := paramsAs[ipc.SiteIDParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.siteRemove(c, p.ID)
	case ipc.MethodSiteSetEnabled:
		p, perr := paramsAs[ipc.SiteEnabledParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.siteSetEnabled(c, p.ID, p.Enabled)
	case ipc.MethodSecretSet:
		p, perr := paramsAs[ipc.SecretSetParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.secretSet(c, p)
	case ipc.MethodSecretStatus:
		st, err := s.secrets.Status(secrets.TunnelToken)
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The secrets could not be read.")
		}
		return ipc.SecretStatusResult{Secrets: []ipc.SecretStatus{{Name: st.Name, Set: st.Set, SetAt: st.SetAt}}}, nil
	case ipc.MethodAuditList:
		p, perr := paramsAs[ipc.AuditListParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.auditList(p)
	case ipc.MethodQuickShareStart:
		p, perr := paramsAs[ipc.QuickShareParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.quickShareStart(c, p.SiteID)
	case ipc.MethodQuickShareStop:
		p, perr := paramsAs[ipc.QuickShareParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.quickShareStop(c, p.SiteID)
	case ipc.MethodTunnelOffline:
		p, perr := paramsAs[ipc.OfflineParams](params)
		if perr != nil {
			return nil, perr
		}
		return s.setOffline(c, p.Offline)
	}
	return nil, ipc.Errorf(ipc.CodeInvalid, "Unknown request.")
}

// paramsAs returns a request's decoded details as *T, or an error if they are
// missing or of another type, instead of panicking (review finding GO-15).
func paramsAs[T any](params any) (*T, *ipc.Error) {
	p, ok := params.(*T)
	if !ok || p == nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "The request's details are missing or not valid.")
	}
	return p, nil
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
func (s *Supervisor) change(c winsec.Caller, action string, detail map[string]string,
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
	rec, err := s.store.Save(next, c.SID, action)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "%v", err)
	}
	detail["revision"] = strconv.FormatUint(rec.Revision, 10)
	s.record(c.SID, action, detail)
	return s.applyOrRestore(rec, cur.Config)
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
			return nil, ipc.Errorf(ipc.CodeInvalid, "The web server could not use these settings: %s", le.reason)
		}
		var back config.Record
		rerr := errors.New("no revision the web server loaded is known")
		if good != 0 {
			back, rerr = s.store.Rollback(good, winsec.SIDSystem)
		}
		if rerr != nil {
			// the last good revision is unknown or cannot be read: restore
			// the settings in force before this change (R-22)
			back, rerr = s.store.Save(prev, winsec.SIDSystem, "Restored the settings before a change the web server refused")
		}
		if rerr != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The web server could not use these settings (%s), and restoring revision %d failed: %v", le.reason, good, rerr)
		}
		s.record(winsec.SIDSystem, "config.restored", map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
			"restored_revision": strconv.FormatUint(good, 10), "new_revision": strconv.FormatUint(back.Revision, 10)})
		_ = s.applyWeb(back)
		return nil, ipc.Errorf(ipc.CodeInvalid, "The web server could not use these settings, so the previous settings were restored. Reason: %s", le.reason)
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

// workerConnected brings a newly connected worker up to date.
func (s *Supervisor) workerConnected(_ context.Context, role string) {
	switch role {
	case ipc.RoleWeb:
		s.changeMu.Lock()
		defer s.changeMu.Unlock()
		rec, err := s.current()
		if err != nil {
			s.web.setState(StateRunning, "The saved settings could not be read: "+err.Error())
			return
		}
		err = s.applyWeb(rec)
		var le *loadError
		if !errors.As(err, &le) {
			return
		}
		if !le.refused {
			// a slow or dying worker says nothing about the settings: report
			// it and keep them, so a change saved while the worker was down
			// is not undone by a slow first load
			s.web.setState(StateRunning, "The web server did not finish loading the saved settings: "+le.reason)
			return
		}
		// At connect time only a known-good revision is restored; with none,
		// the saved settings stay as they are and the reason is reported, so
		// a folder that is missing at boot never wipes the user's sites.
		s.web.setState(StateRunning, "The web server could not use the saved settings: "+le.reason)
		if good := s.store.LastGood(); good != 0 && good != rec.Revision {
			back, err := s.store.Rollback(good, winsec.SIDSystem)
			if err != nil {
				// reported, not hidden (R-22): the saved settings stay as
				// they are until someone fixes or replaces them
				s.web.setState(StateRunning, fmt.Sprintf("The web server could not use the saved settings (%s), and restoring revision %d failed: %v", le.reason, good, err))
				s.record(winsec.SIDSystem, "config.restore_failed", map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
					"restored_revision": strconv.FormatUint(good, 10)})
				return
			}
			s.record(winsec.SIDSystem, "config.restored", map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
				"restored_revision": strconv.FormatUint(good, 10), "new_revision": strconv.FormatUint(back.Revision, 10)})
			_ = s.applyWeb(back)
		}
	case ipc.RoleTunnel:
		// the whole tunnel plan, token included; the token travels only on
		// the tunnel pipe, which only the launcher's account can open (S-23)
		if err := s.pushTunnel(); err != nil && !errors.Is(err, errWorkerDown) {
			s.tunnel.setState(StateRunning, "The tunnel launcher did not take the tunnel settings: "+tunnelErrText(err))
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
	// ones do not needs the same confirmation as adding one, and is audited
	if added := newLANTargets(cur.Config, target.Config); len(added) > 0 {
		if !p.Confirm {
			return nil, ipc.Errorf(ipc.CodeConfirmationRequired,
				"Revision %d forwards to a device on your local network (%s), which makes that device reachable from the internet. Confirm to continue.",
				p.Revision, strings.Join(added, ", "))
		}
		detail["weakening"] = "allow_lan"
	}
	rec, err := s.store.Rollback(p.Revision, c.SID)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeNotFound, "%v", err)
	}
	detail["revision"] = strconv.FormatUint(rec.Revision, 10)
	s.record(c.SID, "config.rollback", detail)
	prev := cur.Config
	if cerr != nil {
		prev = config.Default()
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
	return s.withTunnel(s.change(c, "site.put", detail, func(cfg *config.Config) *ipc.Error {
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
			if !p.Confirm {
				return ipc.Errorf(ipc.CodeConfirmationRequired,
					"Forwarding to a device on your local network makes that device reachable from the internet through this site. Confirm to continue.")
			}
			detail["weakening"] = "allow_lan"
		}
		if i >= 0 {
			cfg.Sites[i] = site
		} else {
			cfg.Sites = append(cfg.Sites, site)
		}
		return nil
	}))
}

func (s *Supervisor) siteRemove(c winsec.Caller, id string) (any, *ipc.Error) {
	return s.withTunnel(s.change(c, "site.remove", map[string]string{"site": id}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites = slices.Delete(cfg.Sites, i, i+1)
		return nil
	}))
}

func (s *Supervisor) siteSetEnabled(c winsec.Caller, id string, enabled bool) (any, *ipc.Error) {
	return s.withTunnel(s.change(c, "site.set_enabled", map[string]string{"site": id, "enabled": strconv.FormatBool(enabled)}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites[i].Enabled = enabled
		return nil
	}))
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
	if st.Set && !p.Confirm {
		return nil, ipc.Errorf(ipc.CodeConfirmationRequired, "A tunnel token is already set. Replacing it changes which tunnel your sites use. Confirm to continue.")
	}
	if err := s.secrets.Set(p.Name, []byte(p.Value)); err != nil {
		return nil, ipc.Errorf(ipc.CodeInvalid, "The token could not be stored: %v", err)
	}
	action := "secret.set"
	if st.Set {
		action = "secret.replace"
	}
	s.record(c.SID, action, map[string]string{"name": p.Name})
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
	rep, err := audit.Verify(path)
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
