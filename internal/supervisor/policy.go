package supervisor

import (
	"context"

	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// methodKind says what a control method may do (review finding SE-29).
type methodKind int

const (
	// kindRead reads state and changes nothing.
	kindRead methodKind = iota + 1
	// kindChange changes state and writes an audit entry naming the caller.
	kindChange
	// kindWeakening changes state and may weaken protection; such a call
	// needs a server-issued confirmation (S-32, SE-27) and its params carry
	// a confirmation field.
	kindWeakening
)

// policy is one method's entry in the table: what it may do, whether it
// accepts a path (the only one is site.put's static folder, which its
// handler resolves and checks, S-31), and its handler.
type policy struct {
	kind      methodKind
	takesPath bool
	handle    func(s *Supervisor, ctx context.Context, c winsec.Caller, params any) (any, *ipc.Error)
}

// policies is the one place a control method is defined on the supervisor
// side. A method missing here is refused before its params are looked at;
// TestEveryMethodHasPolicy keeps it in step with ipc.Methods.
var policies = map[string]policy{
	ipc.MethodStatus: {kind: kindRead, handle: func(s *Supervisor, _ context.Context, _ winsec.Caller, _ any) (any, *ipc.Error) {
		return s.status(), nil
	}},
	ipc.MethodConfigGet: {kind: kindRead, handle: func(s *Supervisor, _ context.Context, _ winsec.Caller, _ any) (any, *ipc.Error) {
		return s.configGet()
	}},
	ipc.MethodConfigHistory: {kind: kindRead, handle: func(s *Supervisor, _ context.Context, _ winsec.Caller, _ any) (any, *ipc.Error) {
		return s.configHistory()
	}},
	ipc.MethodConfigRollback: {kind: kindWeakening, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.RollbackParams) (any, *ipc.Error) {
		return s.rollback(c, p)
	})},
	ipc.MethodConfigExport: {kind: kindRead, handle: func(s *Supervisor, _ context.Context, _ winsec.Caller, _ any) (any, *ipc.Error) {
		return s.configExport()
	}},
	ipc.MethodConfigImport: {kind: kindWeakening, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.ConfigImportParams) (any, *ipc.Error) {
		return s.configImport(c, p)
	})},
	ipc.MethodSitePut: {kind: kindWeakening, takesPath: true, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.SitePutParams) (any, *ipc.Error) {
		return s.sitePut(c, p)
	})},
	ipc.MethodSiteRemove: {kind: kindChange, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.SiteIDParams) (any, *ipc.Error) {
		return s.siteRemove(c, p.ID)
	})},
	ipc.MethodSiteSetEnabled: {kind: kindWeakening, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.SiteEnabledParams) (any, *ipc.Error) {
		return s.siteSetEnabled(c, p)
	})},
	ipc.MethodSecretSet: {kind: kindWeakening, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.SecretSetParams) (any, *ipc.Error) {
		return s.secretSet(c, p)
	})},
	ipc.MethodSecretStatus: {kind: kindRead, handle: func(s *Supervisor, _ context.Context, _ winsec.Caller, _ any) (any, *ipc.Error) {
		st, err := s.secrets.Status(secrets.TunnelToken)
		if err != nil {
			return nil, ipc.Errorf(ipc.CodeInternal, "The secrets could not be read.")
		}
		return ipc.SecretStatusResult{Secrets: []ipc.SecretStatus{{Name: st.Name, Set: st.Set, SetAt: st.SetAt}}}, nil
	}},
	ipc.MethodAuditList: {kind: kindRead, handle: withParams(func(s *Supervisor, _ winsec.Caller, p *ipc.AuditListParams) (any, *ipc.Error) {
		return s.auditList(p)
	})},
	ipc.MethodQuickShareStart: {kind: kindChange, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.QuickShareParams) (any, *ipc.Error) {
		return s.quickShareStart(c, p.SiteID)
	})},
	ipc.MethodQuickShareStop: {kind: kindChange, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.QuickShareParams) (any, *ipc.Error) {
		return s.quickShareStop(c, p.SiteID)
	})},
	ipc.MethodTunnelOffline: {kind: kindChange, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.OfflineParams) (any, *ipc.Error) {
		return s.setOffline(c, p.Offline)
	})},
	ipc.MethodFirewallEvents: {kind: kindRead, handle: withParams(func(s *Supervisor, _ winsec.Caller, p *ipc.FirewallEventsParams) (any, *ipc.Error) {
		return s.firewallEvents(p)
	})},
	ipc.MethodUpdateCheck: {kind: kindChange, handle: func(s *Supervisor, _ context.Context, c winsec.Caller, _ any) (any, *ipc.Error) {
		return s.updateCheck(c)
	}},
	ipc.MethodUpdateSetCheck: {kind: kindWeakening, handle: withParams(func(s *Supervisor, c winsec.Caller, p *ipc.UpdateSetCheckParams) (any, *ipc.Error) {
		return s.updateSetCheck(c, p)
	})},
	ipc.MethodAccessList: {kind: kindRead, handle: withParams(func(s *Supervisor, _ winsec.Caller, p *ipc.AccessListParams) (any, *ipc.Error) {
		return s.accessList(p)
	})},
}

// withParams adapts a handler that takes its method's own params type.
func withParams[T any](f func(s *Supervisor, c winsec.Caller, p *T) (any, *ipc.Error)) func(*Supervisor, context.Context, winsec.Caller, any) (any, *ipc.Error) {
	return func(s *Supervisor, _ context.Context, c winsec.Caller, params any) (any, *ipc.Error) {
		p, perr := paramsAs[T](params)
		if perr != nil {
			return nil, perr
		}
		return f(s, c, p)
	}
}

// handle dispatches one control call through the policy table. Everything
// that reaches it has been decoded strictly into the method's own type by
// ipc.DecodeRequest. The caller is checked again on every call, not only
// when the connection opened (S-30, SE-29).
func (s *Supervisor) handle(ctx context.Context, c winsec.Caller, method string, params any) (any, *ipc.Error) {
	pol, ok := policies[method]
	if !ok {
		return nil, ipc.Errorf(ipc.CodeInvalid, "Unknown request.")
	}
	if !s.authorize(c) {
		return nil, ipc.Errorf(ipc.CodeForbidden, "This account may not control SoiréeHost.")
	}
	return pol.handle(s, ctx, c, params)
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
