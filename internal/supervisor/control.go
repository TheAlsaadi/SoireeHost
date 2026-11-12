package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"

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
		return s.rollback(c, params.(*ipc.RollbackParams).Revision)
	case ipc.MethodSitePut:
		return s.sitePut(c, params.(*ipc.SitePutParams))
	case ipc.MethodSiteRemove:
		return s.siteRemove(c, params.(*ipc.SiteIDParams).ID)
	case ipc.MethodSiteSetEnabled:
		p := params.(*ipc.SiteEnabledParams)
		return s.siteSetEnabled(c, p.ID, p.Enabled)
	case ipc.MethodSecretSet:
		return s.secretSet(c, params.(*ipc.SecretSetParams))
	case ipc.MethodSecretStatus:
		st, err := s.secrets.Status(secrets.TunnelToken)
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The secrets could not be read.")
		}
		return ipc.SecretStatusResult{Secrets: []ipc.SecretStatus{{Name: st.Name, Set: st.Set, SetAt: st.SetAt}}}, nil
	case ipc.MethodAuditList:
		return s.auditList(params.(*ipc.AuditListParams))
	}
	return nil, ipc.Errorf(ipc.CodeInvalid, "Unknown request.")
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
		var rerr error
		if good == 0 {
			back, rerr = s.store.Save(prev, winsec.SIDSystem, "Restored the settings before a change the web server refused")
		} else {
			back, rerr = s.store.Rollback(good, winsec.SIDSystem)
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
	j, err := worker.BuildCaddyJSON(rec.Config, worker.Options{LogDir: s.opts.Paths.WebLogs()})
	if err != nil {
		return &loadError{err.Error()}
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
		// At connect time only a known-good revision is restored; with none,
		// the saved settings stay as they are and the reason is reported, so
		// a folder that is missing at boot never wipes the user's sites.
		s.web.setState(StateRunning, "The web server could not use the saved settings: "+le.reason)
		if good := s.store.LastGood(); good != 0 && good != rec.Revision {
			if back, err := s.store.Rollback(good, winsec.SIDSystem); err == nil {
				s.record(winsec.SIDSystem, "config.restored", map[string]string{"failed_revision": strconv.FormatUint(rec.Revision, 10),
					"restored_revision": strconv.FormatUint(good, 10), "new_revision": strconv.FormatUint(back.Revision, 10)})
				_ = s.applyWeb(back)
			}
		}
	case ipc.RoleTunnel:
		s.sendTunnelToken()
	}
}

// sendTunnelToken hands the tunnel launcher its token, if one is set. The
// token travels only on the tunnel pipe, which only the tunnel launcher's
// account can open (S-23, S-40).
func (s *Supervisor) sendTunnelToken() {
	tok, err := s.secrets.Get(secrets.TunnelToken)
	if err != nil || len(tok) == 0 {
		return
	}
	_ = s.tunnel.load(ipc.WorkerMsg{Type: ipc.MsgLoad, Token: string(tok)})
	clear(tok)
}

func (s *Supervisor) rollback(c winsec.Caller, rev uint64) (any, *ipc.Error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	rec, err := s.store.Rollback(rev, c.SID)
	if err != nil {
		return nil, ipc.Errorf(ipc.CodeNotFound, "%v", err)
	}
	s.record(c.SID, "config.rollback", map[string]string{"to_revision": strconv.FormatUint(rev, 10), "revision": strconv.FormatUint(rec.Revision, 10)})
	return s.applyOrRestore(rec, config.Default())
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
			if ok, err := s.opts.WorkerCanRead(canon); err == nil && !ok {
				return nil, ipc.Errorf(ipc.CodeInvalid, "The web server is not allowed to read %s. Add the site from the control panel, which grants read access, or give NT SERVICE\\%s read access to the folder.", canon, winsec.WebService)
			}
		}
		site.Static.Root = canon
		detail["root"] = canon
	}
	if site.Proxy != nil {
		detail["target"] = site.Proxy.Target
	}
	return s.change(c, "site.put", detail, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == site.ID })
		hadLAN := i >= 0 && cfg.Sites[i].Proxy != nil && cfg.Sites[i].Proxy.AllowLAN
		if site.Proxy != nil && site.Proxy.AllowLAN && !hadLAN {
			// S-32: a LAN target is a weakening change
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
	})
}

func (s *Supervisor) siteRemove(c winsec.Caller, id string) (any, *ipc.Error) {
	return s.change(c, "site.remove", map[string]string{"site": id}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites = slices.Delete(cfg.Sites, i, i+1)
		return nil
	})
}

func (s *Supervisor) siteSetEnabled(c winsec.Caller, id string, enabled bool) (any, *ipc.Error) {
	return s.change(c, "site.set_enabled", map[string]string{"site": id, "enabled": strconv.FormatBool(enabled)}, func(cfg *config.Config) *ipc.Error {
		i := slices.IndexFunc(cfg.Sites, func(x config.Site) bool { return x.ID == id })
		if i < 0 {
			return ipc.Errorf(ipc.CodeNotFound, "There is no site %q.", id)
		}
		cfg.Sites[i].Enabled = enabled
		return nil
	})
}

// secretSet stores the tunnel token (write-only, S-35). Replacing a token
// that is already set changes the tunnel, so it needs confirmation (S-32).
func (s *Supervisor) secretSet(c winsec.Caller, p *ipc.SecretSetParams) (any, *ipc.Error) {
	if p.Name != secrets.TunnelToken {
		return nil, ipc.Errorf(ipc.CodeInvalid, "Unknown secret %q.", p.Name)
	}
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
	go s.sendTunnelToken()
	st, _ = s.secrets.Status(p.Name)
	return ipc.SecretStatusResult{Secrets: []ipc.SecretStatus{{Name: st.Name, Set: st.Set, SetAt: st.SetAt}}}, nil
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
