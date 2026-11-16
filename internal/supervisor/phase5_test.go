package supervisor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TheAlsaadi/SoireeHost/internal/accesslog"
	"github.com/TheAlsaadi/SoireeHost/internal/config"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/testutil"
	"github.com/TheAlsaadi/SoireeHost/internal/winsec"
)

// SE-29: every control method has exactly one policy entry, and every
// entry is a method the control API decodes.
func TestEveryMethodHasPolicy(t *testing.T) {
	methods := ipc.Methods()
	for _, m := range methods {
		if _, ok := policies[m]; !ok {
			t.Errorf("method %s has no policy", m)
		}
	}
	for m, p := range policies {
		if !slices.Contains(methods, m) {
			t.Errorf("policy for %s, which is not a control method", m)
		}
		if p.kind < kindRead || p.kind > kindWeakening || p.handle == nil {
			t.Errorf("policy for %s is incomplete", m)
		}
		if p.takesPath && m != ipc.MethodSitePut {
			t.Errorf("%s takes a path; only site.put may (S-31)", m)
		}
	}
}

// SE-29, SE-27: a weakening method's params carry a confirmation field and
// no other method's do, so no method can skip or fake the server-issued
// confirmation.
func TestWeakeningMethodsTakeConfirmation(t *testing.T) {
	for _, m := range ipc.Methods() {
		_, params, err := ipc.DecodeRequest([]byte(`{"id":1,"method":"` + m + `","params":{}}`))
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		_, has := reflect.TypeOf(params).Elem().FieldByName("Confirmation")
		if want := policies[m].kind == kindWeakening; has != want {
			t.Errorf("%s: confirmation field %v, weakening %v", m, has, want)
		}
		// the old client-set flag is gone everywhere
		if _, old := reflect.TypeOf(params).Elem().FieldByName("Confirm"); old {
			t.Errorf("%s still has a Confirm flag", m)
		}
	}
}

// SE-29: an unknown method is refused before any handler runs, and a caller
// that is no longer admitted is refused on its next call.
func TestPolicyRefusesUnknownAndUnadmitted(t *testing.T) {
	h := start(t)
	me, err := winsec.CurrentCaller()
	if err != nil {
		t.Fatal(err)
	}
	if _, e := h.sup.handle(t.Context(), me, "site.wipe", nil); e == nil || e.Code != ipc.CodeInvalid {
		t.Fatalf("unknown method: %v", e)
	}
	h.sup.users = nil
	stranger := winsec.Caller{SID: "S-1-5-21-1-2-3-4242"}
	if _, e := h.sup.handle(t.Context(), stranger, ipc.MethodStatus, &ipc.None{}); e == nil || e.Code != ipc.CodeForbidden {
		t.Fatalf("unadmitted caller: %v", e)
	}
}

func confirmationOf(t *testing.T, err error) *ipc.Confirmation {
	t.Helper()
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.CodeConfirmationRequired || e.Confirmation == nil || len(e.Confirmation.Token) != 32 {
		t.Fatalf("want confirmation_required with a token, got %v", err)
	}
	if len(e.Confirmation.Sentences) == 0 || time.Until(e.Confirmation.Expires) <= 0 {
		t.Fatalf("confirmation without sentences or already expired: %+v", e.Confirmation)
	}
	return e.Confirmation
}

// SE-27: a confirmation token works once, for the same call only.
func TestConfirmationTokenSingleUseAndBound(t *testing.T) {
	h := start(t)
	nas := h.proxySite("nas", "192.168.1.20:5000")
	nas.Proxy.AllowLAN = true
	other := h.proxySite("nas", "192.168.1.21:5000")
	other.Proxy.AllowLAN = true

	conf := confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: nas}, nil))
	// made-up token
	confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: nas, Confirmation: strings.Repeat("ab", 16)}, nil))
	// right token, other parameters: refused, and the token is spent
	confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: other, Confirmation: conf.Token}, nil))
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: nas, Confirmation: conf.Token}, nil); err == nil {
		t.Fatal("a token was accepted after it was spent on another call")
	}
	// a fresh token, used for the call it was issued for: accepted once
	conf = confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: nas}, nil))
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: nas, Confirmation: conf.Token}, nil); err != nil {
		t.Fatalf("valid confirmation refused: %v", err)
	}
	// replaying it is refused (another LAN device, so still weakening)
	confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: other, Confirmation: conf.Token}, nil))
}

// SE-27: tokens expire, belong to the caller they were issued to, and a
// caller holds a bounded number of them.
func TestConfirmationStore(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	cs := newConfirmations(func() time.Time { return now })
	d, err := digestOf(ipc.SitePutParams{}, []string{"weaker"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := cs.issue("S-1-5-21-1", ipc.MethodSitePut, d, []string{"weaker"})
	if err != nil {
		t.Fatal(err)
	}
	if cs.consume(c.Token, "S-1-5-21-2", ipc.MethodSitePut, d) {
		t.Fatal("another caller's token was accepted")
	}
	c, _ = cs.issue("S-1-5-21-1", ipc.MethodSitePut, d, []string{"weaker"})
	if cs.consume(c.Token, "S-1-5-21-1", ipc.MethodConfigImport, d) {
		t.Fatal("a token was accepted for another method")
	}
	c, _ = cs.issue("S-1-5-21-1", ipc.MethodSitePut, d, []string{"weaker"})
	now = now.Add(ipc.ConfirmationTTL + time.Second)
	if cs.consume(c.Token, "S-1-5-21-1", ipc.MethodSitePut, d) {
		t.Fatal("an expired token was accepted")
	}
	d2, _ := digestOf(ipc.SitePutParams{}, []string{"weaker", "and more"})
	c, _ = cs.issue("S-1-5-21-1", ipc.MethodSitePut, d, []string{"weaker"})
	if cs.consume(c.Token, "S-1-5-21-1", ipc.MethodSitePut, d2) {
		t.Fatal("a token was accepted for a change described differently")
	}
	var first *ipc.Confirmation
	for i := range maxConfirmationsPerCaller + 1 {
		now = now.Add(time.Millisecond)
		c, _ := cs.issue("S-1-5-21-9", ipc.MethodSitePut, d, []string{"weaker"})
		if i == 0 {
			first = c
		}
	}
	n := 0
	for _, x := range cs.open {
		if x.sid == "S-1-5-21-9" {
			n++
		}
	}
	if n != maxConfirmationsPerCaller {
		t.Fatalf("caller holds %d tokens, want %d", n, maxConfirmationsPerCaller)
	}
	if cs.consume(first.Token, "S-1-5-21-9", ipc.MethodSitePut, d) {
		t.Fatal("the oldest token was not dropped")
	}
}

// SE-28: removing a security header is a weakening change that needs
// confirmation, and the warning names it.
func TestRemovingHeaderNeedsConfirmation(t *testing.T) {
	h := start(t)
	site := h.proxySite("app", "127.0.0.1:3000")
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	site.RemoveHeaders = []string{"Content-Security-Policy"}
	conf := confirmationOf(t, h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil))
	if !strings.Contains(strings.Join(conf.Sentences, " "), "Content-Security-Policy") {
		t.Fatalf("sentences do not name the header: %v", conf.Sentences)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site, Confirmation: conf.Token}, &res); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "does not send Content-Security-Policy") }) {
		t.Fatalf("no standing warning: %v", res.Warnings)
	}
	site.ResponseHeaders = map[string]string{"X-Content-Type-Options": ""}
	var e *ipc.Error
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
		t.Fatalf("an empty header value was not refused: %v", err)
	}
}

// writeLog writes lines into the web worker's log folder.
func writeLog(t *testing.T, h *harness, name string, lines ...string) {
	t.Helper()
	dir := h.paths.WebLogs()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func accessLine(t *testing.T, ts time.Time, host, uri, ua string, status int) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"level": "info", "ts": float64(ts.UnixNano()) / 1e9, "logger": "http.log.access.access", "msg": "handled request",
		"request": map[string]any{"client_ip": "198.51.100.7", "method": "GET", "host": host, "uri": uri,
			"headers": map[string][]string{"User-Agent": {ua}}},
		"status": status, "size": 12, "duration": 0.002,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// access.list maps requests to their site, matches a blocked one to the
// firewall rule that fired, and returns attacker text as data (S-34): the
// script stays a literal string for the control panel to show as text.
func TestAccessListJoinsFirewallEvents(t *testing.T) {
	h := start(t)
	site := h.proxySite("app", "127.0.0.1:3000")
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	host := site.Hostnames[0]
	t0 := time.Now().Add(-time.Minute).UTC()
	evil := "/<script>alert(1)</script>"
	ua := "<img src=x onerror=alert(1)> \u202Efdp.exe"
	writeLog(t, h, accesslog.LogName,
		accessLine(t, t0, host, "/index.html", "Mozilla/5.0", 200),
		accessLine(t, t0.Add(time.Second), host, evil, ua, 403),
		accessLine(t, t0.Add(2*time.Second), "other.example.net", "/", "curl", 404),
		`{"logger":"http.log.access.access","status":200,"ts":"not a number"}`,
	)
	ev, err := json.Marshal(map[string]any{"level": "warn", "ts": 1, "logger": "http.handlers.waf", "msg": "firewall event",
		"event": map[string]any{"time": t0.Add(time.Second), "site": "app", "mode": "block", "action": "blocked", "status": 403,
			"paranoia_level": 1, "method": "GET", "host": host, "uri": evil, "client_ip": "198.51.100.7",
			"rules": []map[string]any{{"id": 941100, "severity": "critical", "msg": "XSS Attack Detected via libinjection", "where": []string{"REQUEST_FILENAME"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	writeLog(t, h, "firewall.log", string(ev))

	var res ipc.AccessListResult
	if err := h.call(ipc.MethodAccessList, ipc.AccessListParams{}, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 3 || res.Skipped != 1 {
		t.Fatalf("entries %d skipped %d: %+v", len(res.Entries), res.Skipped, res.Entries)
	}
	blocked := res.Entries[1]
	if blocked.URI != evil || blocked.UserAgent != ua || blocked.SiteID != "app" {
		t.Fatalf("blocked entry changed or unmapped: %+v", blocked)
	}
	if blocked.Firewall == nil || blocked.Firewall.Action != "blocked" || blocked.Firewall.Rules[0].ID != 941100 {
		t.Fatalf("blocked entry not matched to its rule: %+v", blocked.Firewall)
	}
	if res.Entries[0].SiteID != "" || res.Entries[2].Firewall != nil {
		t.Fatalf("wrong site or match: %+v", res.Entries)
	}
	var only ipc.AccessListResult
	if err := h.call(ipc.MethodAccessList, ipc.AccessListParams{Class: accesslog.ClassBlocked}, &only); err != nil || len(only.Entries) != 1 {
		t.Fatalf("blocked filter: %v %+v", err, only.Entries)
	}
	if err := h.call(ipc.MethodAccessList, ipc.AccessListParams{SiteID: "app"}, &only); err != nil || len(only.Entries) != 2 {
		t.Fatalf("site filter: %v %+v", err, only.Entries)
	}
	var e *ipc.Error
	if err := h.call(ipc.MethodAccessList, ipc.AccessListParams{Class: "everything"}, nil); !errors.As(err, &e) || e.Code != ipc.CodeInvalid {
		t.Fatalf("bad class: %v", err)
	}
}

// config.import always needs confirmation (S-32) and brings static sites in
// switched off, so each folder is checked before it goes live (ADR-0008).
func TestConfigImport(t *testing.T) {
	h := start(t)
	root := testutil.SiteDir(t)
	cfg := config.Default()
	cfg.Sites = []config.Site{
		{ID: "blog", Name: "Blog", Enabled: true, Hostnames: []string{"blog.example.com"}, Type: config.TypeStatic, Static: &config.Static{Root: root}},
		h.proxySite("app", "127.0.0.1:3000"),
	}
	conf := confirmationOf(t, h.call(ipc.MethodConfigImport, ipc.ConfigImportParams{Config: cfg}, nil))
	if !strings.Contains(conf.Sentences[0], "replaces all your settings") {
		t.Fatalf("sentences: %v", conf.Sentences)
	}
	var res ipc.ConfigResult
	if err := h.call(ipc.MethodConfigImport, ipc.ConfigImportParams{Config: cfg, Confirmation: conf.Token}, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Config.Sites) != 2 || res.Config.Sites[0].Enabled || !res.Config.Sites[1].Enabled {
		t.Fatalf("imported sites: %+v", res.Config.Sites)
	}
	var exp ipc.ConfigExportResult
	if err := h.call(ipc.MethodConfigExport, ipc.None{}, &exp); err != nil || exp.Revision != res.Revision || len(exp.Config.Sites) != 2 {
		t.Fatalf("export: %v %+v", err, exp)
	}
	// an export from an earlier version with an empty header value imports
	// as a removed header (SE-28)
	legacy := cfg
	legacy.Sites = []config.Site{h.proxySite("app", "127.0.0.1:3000")}
	legacy.Sites[0].ResponseHeaders = map[string]string{"Referrer-Policy": ""}
	conf = confirmationOf(t, h.call(ipc.MethodConfigImport, ipc.ConfigImportParams{Config: legacy}, nil))
	if err := h.call(ipc.MethodConfigImport, ipc.ConfigImportParams{Config: legacy, Confirmation: conf.Token}, &res); err != nil {
		t.Fatal(err)
	}
	if got := res.Config.Sites[0].RemoveHeaders; len(got) != 1 || got[0] != "Referrer-Policy" {
		t.Fatalf("legacy empty header not migrated: %+v", res.Config.Sites[0])
	}
}

// SE-28, S-32: going back to a revision that sent fewer security headers
// needs the same confirmation as removing one (security review, 16 Nov 2026).
func TestRollbackToWeakerHeadersNeedsConfirmation(t *testing.T) {
	h := start(t)
	site := h.proxySite("app", "127.0.0.1:3000")
	site.RemoveHeaders = []string{"Referrer-Policy"}
	var weak ipc.ConfigResult
	if err := h.confirmed(ipc.MethodSitePut, &ipc.SitePutParams{Site: site}, &weak); err != nil {
		t.Fatal(err)
	}
	site.RemoveHeaders = nil
	if err := h.call(ipc.MethodSitePut, ipc.SitePutParams{Site: site}, nil); err != nil {
		t.Fatal(err)
	}
	conf := confirmationOf(t, h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: weak.Revision}, nil))
	if !strings.Contains(strings.Join(conf.Sentences, " "), "Referrer-Policy") {
		t.Fatalf("sentences: %v", conf.Sentences)
	}
	if err := h.call(ipc.MethodConfigRollback, ipc.RollbackParams{Revision: weak.Revision, Confirmation: conf.Token}, nil); err != nil {
		t.Fatal(err)
	}
}
