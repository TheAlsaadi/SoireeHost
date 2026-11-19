// FAKE_SUPERVISOR_FOR_DEVELOPMENT_ONLY
// A stand-in supervisor for working on screens without installed services.
// Loaded only by the Vite development server with VITE_FAKE=1; a release
// bundle that contains the marker above is refused by build/check-bundle.mjs.

import type { Api, config, ipc } from "./api";

const now = () => new Date().toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

function site(id: string, name: string, type: "static" | "proxy", extra: Partial<config.Site>): config.Site {
  return {
    id,
    name,
    enabled: true,
    hostnames: [],
    type,
    static: type === "static" ? { root: "C:\\Sites\\" + id, directory_listing: false } : null,
    proxy: null,
    max_body_bytes: 0,
    rate_limit_per_minute: 0,
    allow_well_known: false,
    firewall: { mode: "block", paranoia_level: 1 },
    ...extra,
  };
}

export function fakeApi(): Api {
  const cfg: config.Config = {
    version: 1,
    listen: "127.0.0.1:8787",
    server: { max_header_bytes: 65536, read_header_timeout_seconds: 10, read_timeout_seconds: 300, idle_timeout_seconds: 120 },
    tunnel: { offline: false, metrics_port: 20300 },
    updates: { off: false },
    sites: [
      site("recipes", "Recipe notes", "static", { quick_share: { port: 8788, metrics_port: 20301 } }),
      site("budget", "Budget tracker", "proxy", { static: null, proxy: { target: "127.0.0.1:3000", allow_lan: false }, quick_share: { port: 8789, metrics_port: 20302 } }),
      site("notes-api", "Notes API", "proxy", { static: null, proxy: { target: "127.0.0.1:8000", allow_lan: false }, firewall: { mode: "detect", paranoia_level: 1 } }),
      site("portfolio", "Old portfolio", "static", { enabled: false }),
    ],
  };
  let revision = 12;
  let offline = false;
  const result = (): ipc.ConfigResult => ({ revision, config: structuredClone(cfg), warnings: ['Site "notes-api" is set to Detect only: attacks are logged but not blocked.'] });
  const status = (): ipc.StatusResult => ({
    version: "0.5.0-dev",
    state: "running",
    revision,
    workers: [],
    audit_ok: true,
    started_at: ago(3600),
    update: { state: "idle", last_check: ago(7200) },
    tunnel: {
      offline,
      token_set: false,
      service_url: "http://127.0.0.1:8787",
      repair_needed: false,
      tunnels: offline
        ? []
        : [
            { kind: "quick", site_id: "recipes", state: "connected", connections: 4, url: "https://plain-river-tide.trycloudflare.com", temporary: true, label: "Temporary link for testing. It changes whenever the tunnel restarts.", since: ago(900) },
            { kind: "quick", site_id: "budget", state: "connected", connections: 4, url: "https://amber-coast-lamp.trycloudflare.com", temporary: true, since: ago(600) },
          ],
    },
  });
  const entry = (s: number, siteId: string, host: string, method: string, uri: string, st: number, ua = "Mozilla/5.0", fw?: ipc.FirewallMatch): ipc.AccessEntry => ({
    time: ago(s), method, host, uri, status: st, client_ip: fw ? "198.51.100.7" : "203.0.113.24", user_agent: ua, size: 1200, duration_ms: 3, site_id: siteId, firewall: fw ?? null,
  });
  const xss: ipc.FirewallMatch = {
    action: "blocked",
    rules: [
      { id: 941100, severity: "critical", msg: "XSS Attack Detected via libinjection", where: ["REQUEST_FILENAME"] },
      { id: 941160, severity: "critical", msg: "NoScript XSS InjectionChecker: HTML Injection", where: ["REQUEST_FILENAME"] },
    ],
  };
  const host = "plain-river-tide.trycloudflare.com";
  const rlo = String.fromCodePoint(0x202e);
  const log: ipc.AccessEntry[] = [
    entry(2, "recipes", host, "GET", "/soup/lentil.html", 200),
    entry(4, "recipes", host, "GET", "/<script>alert(1)</script>", 403, "<img src=x onerror=alert(1)> " + rlo + "fdp.exe", xss),
    entry(13, "budget", "amber-coast-lamp.trycloudflare.com", "GET", "/api/summary", 502),
    entry(25, "recipes", host, "GET", "/.env", 404),
    entry(48, "recipes", host, "GET", "/search?q=REDACTED", 403, "sqlmap/1.8", { action: "blocked", rules: [{ id: 942100, severity: "critical", msg: "SQL Injection Attack Detected via libinjection", where: ["ARGS"] }] }),
    entry(53, "recipes", host, "GET", "/", 200),
    entry(91, "budget", "amber-coast-lamp.trycloudflare.com", "POST", "/api/entries", 201),
    entry(116, "recipes", host, "GET", "/styles.css", 304),
  ];
  const change = () => {
    revision++;
    return result();
  };
  const fail = (code: string, message: string, confirmation?: ipc.SecretStatusResult | object) =>
    Promise.reject(Object.assign(new Error(message), { cause: { code, message, ...(confirmation ? { confirmation } : {}) } }));

  return {
    version: async () => "0.5.0-dev",
    status: async () => status(),
    config: async () => result(),
    putSite: async (s, tok) => {
      if (s.firewall.mode !== "block" && !tok) {
        return fail("confirmation_required", "Confirm.", { token: "f".repeat(32), sentences: [`Site "${s.id}" weakens its firewall.`], expires: now() });
      }
      const i = cfg.sites.findIndex((x) => x.id === s.id);
      if (i >= 0) cfg.sites[i] = s;
      else cfg.sites.push(s);
      return change();
    },
    setSiteEnabled: async (id, on) => {
      const s = cfg.sites.find((x) => x.id === id);
      if (s) s.enabled = on;
      return change();
    },
    removeSite: async (id) => {
      cfg.sites = cfg.sites.filter((x) => x.id !== id);
      return change();
    },
    startQuickShare: async (id) => {
      const s = cfg.sites.find((x) => x.id === id);
      if (s) s.quick_share = { port: 8790, metrics_port: 20303 };
      return change();
    },
    stopQuickShare: async (id) => {
      const s = cfg.sites.find((x) => x.id === id);
      if (s) s.quick_share = null;
      return change();
    },
    setOffline: async (o) => {
      offline = o;
      return change();
    },
    activity: async (p) => ({
      entries: log.filter((e) => (!p.site_id || e.site_id === p.site_id) && (!p.after || e.time > p.after) && (p.class !== "blocked" || e.firewall?.action === "blocked")),
      skipped: 0,
      more: false,
    }),
    auditList: async () => ({ entries: [], report: { entries: 148 } }),
    history: async () => ({
      revisions: [11, 10, 9].map((r) => ({ revision: r, saved_at: ago(r * 3600), actor: "S-1-5-21-1", summary: "site.put", config: cfg })) as unknown as config.Record[],
      last_good: revision,
    }),
    rollback: async () => change(),
    secretStatus: async () => ({ secrets: [{ name: "tunnel_token", set: false }] }),
    setTunnelToken: async () => ({ secrets: [{ name: "tunnel_token", set: true, set_at: now() }] }),
    exportConfig: async () => JSON.stringify(cfg, null, 2),
    importConfig: async () => fail("confirmation_required", "Confirm.", { token: "e".repeat(32), sentences: ["Importing replaces all your settings: 4 site(s) now, 4 after the import."], expires: now() }),
    confirmImport: async () => change(),
    chooseFolder: async () => "C:\\Sites\\new-site",
    prepareFolder: async (p) => p,
    listeningPorts: async () => [
      { port: 3000, process: "node.exe", loopback: true, ipv4: true, ipv6: false },
      { port: 5173, process: "node.exe", loopback: true, ipv4: true, ipv6: false },
      { port: 8000, process: "python.exe", loopback: true, ipv4: true, ipv6: false },
    ],
    qrCode: async () => {
      const size = 25;
      return { size, modules: Array.from({ length: size }, (_, y) => Array.from({ length: size }, (_, x) => (x * 7 + y * 13) % 5 < 2 || (x < 7 && y < 7))) };
    },
    openKnownLink: async () => {},
    openSiteAddress: async () => {},
    copyText: async () => true,
    saveExport: async () => true,
    openImport: async () => "{}",
    startAtSignIn: async () => true,
    setStartAtSignIn: async () => {},
    onFolderDropped: () => () => {},
    checkForUpdates: async () => ({ state: "checking", last_check: ago(7200) }),
    setUpdateCheck: async (check) => {
      cfg.updates.off = !check;
      revision++;
      return result();
    },
    // ?setup=not_installed, other_copy or uninstall shows a setup window in
    // the development fake
    setupState: async () => ({
      mode: new URLSearchParams(location.search).get("setup") ?? "installed",
      installed_version: "1.2.0",
      this_version: "1.3.0",
      newer: true,
    }),
    runSetup: async () => {
      await new Promise((r) => setTimeout(r, 800));
      return { code: 0, cancelled: false };
    },
    openInstalled: async () => {},
    closeSetup: async () => {},
  };
}
