// Turns the supervisor's state into plain words (plan section 7): the one
// status line on every screen, each site's status and health line, and the
// address a site is reached at. Pure functions, so they are unit-tested.

import type { config, ipc, gui } from "./api";
import type { MessageKey } from "./i18n/en";

export type Tone = "ok" | "warning" | "danger" | "off";

export interface Said {
  tone: Tone;
  key: MessageKey;
  params?: Record<string, string | number>;
}

// The supervisor saves each version with the name of the change that made
// it; Backups shows these as sentences instead.
const changeNames: Record<string, MessageKey> = {
  "site.put": "backups.change.sitePut",
  "site.remove": "backups.change.siteRemove",
  "site.set_enabled": "backups.change.siteEnabled",
  "quickshare.start": "backups.change.quickShareStart",
  "quickshare.stop": "backups.change.quickShareStop",
  "tunnel.set_offline": "backups.change.offline",
  "config.import": "backups.change.import",
  "Restored the settings before a change the web server refused": "backups.change.autoRestore",
};

/** A saved version's summary in plain words, or undefined to show it as it is. */
export function revisionSummary(summary: string): { key: MessageKey; params?: Record<string, string | number> } | undefined {
  const key = Object.hasOwn(changeNames, summary) ? changeNames[summary] : undefined;
  if (key) return { key };
  const n = /^Rolled back to revision (\d+)$/.exec(summary)?.[1];
  return n ? { key: "backups.change.rollback", params: { n } } : undefined;
}

function quickTunnel(site: config.Site, st: ipc.StatusResult | undefined): ipc.TunnelView | undefined {
  return st?.tunnel.tunnels.find((t) => t.kind === "quick" && t.site_id === site.id);
}

function tokenTunnel(st: ipc.StatusResult | undefined): ipc.TunnelView | undefined {
  return st?.tunnel.tunnels.find((t) => t.kind === "token");
}

/** Whether the site's address is a temporary quick share link (S-51). */
export function addressIsTemporary(site: config.Site, st: ipc.StatusResult | undefined): boolean {
  const q = quickTunnel(site, st);
  return !!q?.url && q.temporary;
}

/** The address a site is reached at, or "" if it has none yet. */
export function siteAddress(site: config.Site, st: ipc.StatusResult | undefined): string {
  const q = quickTunnel(site, st);
  if (q?.url) return q.url;
  if (site.hostnames.length > 0 && st?.tunnel.token_set) return "https://" + site.hostnames[0];
  return "";
}

/** Whether a site is served through a connected tunnel right now. */
export function siteOnline(site: config.Site, st: ipc.StatusResult | undefined): boolean {
  if (!site.enabled || !st || st.tunnel.offline) return false;
  if (quickTunnel(site, st)?.state === "connected") return true;
  return site.hostnames.length > 0 && tokenTunnel(st)?.state === "connected";
}

/** The port a proxy site forwards to, or 0. */
export function proxyPort(site: config.Site): number {
  const t = site.proxy?.target ?? "";
  const n = Number(t.slice(t.lastIndexOf(":") + 1));
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : 0;
}

/**
 * A site's status in a few words. ports, when known, lets a proxy site say
 * that its app is not answering ("Port 3000 is not answering").
 */
export function siteStatus(site: config.Site, st: ipc.StatusResult | undefined, ports?: gui.Port[]): Said {
  if (!site.enabled) return { tone: "off", key: "site.status.stopped" };
  const port = proxyPort(site);
  if (site.type === "proxy" && ports && port && !ports.some((p) => p.port === port)) {
    return { tone: "warning", key: "site.status.portDown", params: { port } };
  }
  const q = quickTunnel(site, st);
  if (q && (q.state === "starting" || q.state === "reconnecting")) return { tone: "warning", key: "site.status.connecting" };
  if (siteOnline(site, st)) return { tone: "ok", key: "site.status.online" };
  return { tone: "off", key: "site.status.notOnline" };
}

/** The one sentence at the top of every screen. */
export function statusLine(st: ipc.StatusResult | undefined, cfg: config.Config | undefined, failed: boolean): Said {
  if (failed) return { tone: "danger", key: "statusline.noService" };
  if (!st || !cfg) return { tone: "off", key: "statusline.checking" };
  if (st.tunnel.offline) return { tone: "off", key: "statusline.offline" };
  if (st.tunnel.repair_needed) return { tone: "danger", key: "statusline.repair" };
  if (st.update.state === "interrupted") return { tone: "danger", key: "statusline.updateInterrupted" };
  const enabled = cfg.sites.filter((s) => s.enabled);
  if (cfg.sites.length === 0) return { tone: "off", key: "statusline.noSites" };
  const online = enabled.filter((s) => siteOnline(s, st)).length;
  if (online > 0) return { tone: "ok", key: "statusline.online", params: { online, total: enabled.length } };
  const down = st.tunnel.tunnels.find((t) => t.state === "down" || t.state === "reconnecting");
  if (down?.since) return { tone: "danger", key: "statusline.downSince", params: { time: clock(down.since) } };
  return { tone: "warning", key: "statusline.notOnline" };
}

/** Local time of day, 24-hour, for status sentences. */
export function clock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

/** Local time with seconds, for log rows. */
export function clockSeconds(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** A date and time, for detail panes ("15 Nov 2026, 14:02"). */
export function dateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Megabytes, for limits. */
export function megabytes(bytes: number): number {
  return Math.round(bytes / (1 << 20));
}

/** A site id made from its name: lower-case letters, digits and dashes. */
export function idFromName(name: string, taken: string[]): string {
  const base =
    name
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 24) || "site";
  let id = base;
  for (let i = 2; taken.includes(id); i++) id = `${base}-${i}`;
  return id;
}

/**
 * The proxy target for an app on port n: [::1] when it listens on the IPv6
 * loopback address only (as many development servers do), 127.0.0.1
 * otherwise. Both are this PC's own address (S-10).
 */
export function proxyTarget(n: number, ports: gui.Port[] | undefined): string {
  const p = ports?.find((x) => x.port === n);
  return (p && p.ipv6 && !p.ipv4 ? "[::1]:" : "127.0.0.1:") + n;
}
