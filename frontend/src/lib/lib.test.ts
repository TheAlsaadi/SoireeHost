import { describe, expect, it } from "vitest";
import { segments, visibleText } from "./visible";
import { needsConfirmation, toApiError } from "./errors";
import { idFromName, proxyPort, siteAddress, siteOnline, siteStatus, statusLine } from "./status";
import { t } from "./i18n";
import { en } from "./i18n/en";
import type { config, ipc } from "./api";

const cp = (n: number) => String.fromCodePoint(n);

describe("visible text (S-34)", () => {
  it("keeps markup as literal text", () => {
    expect(segments("<script>alert(1)</script>")).toEqual([{ text: "<script>alert(1)</script>", marker: false }]);
  });

  it("shows hidden characters as markers", () => {
    const rlo = cp(0x202e);
    const zw = cp(0x200b);
    const nl = cp(0x0a);
    const s = segments("invoice" + rlo + "fdp.exe" + zw + nl + "x");
    expect(s.filter((p) => p.marker).map((p) => p.text)).toEqual(["U+202E", "U+200B", "U+000A"]);
    expect(s.map((p) => p.text).join("")).not.toContain(rlo);
    expect(visibleText("a" + cp(0x2066) + "b")).toBe("a[U+2066]b");
  });

  it("cuts long text with an ellipsis", () => {
    const s = segments("x".repeat(500), 20);
    expect(s.at(-1)?.text).toBe("…");
    expect(s.map((p) => p.text).join("").length).toBeLessThanOrEqual(21);
  });
});

describe("errors", () => {
  it("reads the supervisor's error from the cause", () => {
    const e = toApiError({ cause: { code: "confirmation_required", message: "Confirm.", worker_detail: "busy", confirmation: { token: "ab", sentences: ["Weaker."], expires: "" } } });
    expect(e.code).toBe("confirmation_required");
    expect(e.workerDetail).toBe("busy");
    expect(needsConfirmation(e)).toBe(true);
  });

  it("reads a cause sent as JSON text and refuses unknown codes", () => {
    expect(toApiError({ cause: '{"code":"invalid","message":"No."}' }).message).toBe("No.");
    expect(toApiError({ cause: { code: "pwned", message: "x" } }).code).toBe("unavailable");
    expect(toApiError(new Error("boom")).code).toBe("unavailable");
  });
});

function site(over: Partial<config.Site>): config.Site {
  return {
    id: "blog",
    name: "Blog",
    enabled: true,
    hostnames: [],
    type: "static",
    max_body_bytes: 0,
    rate_limit_per_minute: 0,
    allow_well_known: false,
    firewall: { mode: "block", paranoia_level: 1 },
    ...over,
  };
}

function status(tunnels: ipc.TunnelView[], over: Partial<ipc.TunnelStatus> = {}): ipc.StatusResult {
  return {
    version: "1.0.0",
    state: "running",
    revision: 1,
    workers: [],
    audit_ok: true,
    started_at: "",
    tunnel: { offline: false, token_set: false, service_url: "", repair_needed: false, tunnels, ...over },
  };
}

describe("status in plain words", () => {
  const quick: ipc.TunnelView = { kind: "quick", site_id: "blog", state: "connected", connections: 4, url: "https://a-b-c.trycloudflare.com", temporary: true };

  it("says a shared site is online and gives its address", () => {
    const st = status([quick]);
    expect(siteOnline(site({}), st)).toBe(true);
    expect(siteAddress(site({}), st)).toBe("https://a-b-c.trycloudflare.com");
    const line = statusLine(st, { sites: [site({})] } as config.Config, false);
    expect(t(line.key, line.params)).toBe("1 of 1 sites served through Cloudflare Tunnel");
  });

  it("names the port of a proxy site whose app is not answering", () => {
    const s = site({ type: "proxy", proxy: { target: "127.0.0.1:3000", allow_lan: false } });
    expect(proxyPort(s)).toBe(3000);
    const said = siteStatus(s, status([quick]), [{ port: 8000, process: "python.exe", loopback: true, ipv4: true, ipv6: false }]);
    expect(t(said.key, said.params)).toBe("Port 3000 is not answering");
  });

  it("says offline, service down and stopped", () => {
    expect(statusLine(status([], { offline: true }), { sites: [site({})] } as config.Config, false).key).toBe("statusline.offline");
    expect(statusLine(undefined, undefined, true).key).toBe("statusline.noService");
    expect(siteStatus(site({ enabled: false }), status([quick])).key).toBe("site.status.stopped");
  });

  it("makes site ids from names", () => {
    expect(idFromName("Recipe notes!", [])).toBe("recipe-notes");
    expect(idFromName("Recipe notes", ["recipe-notes"])).toBe("recipe-notes-2");
    expect(idFromName("???", [])).toBe("site");
  });
});

describe("message catalogue", () => {
  it("fills parameters as text and leaves unknown ones alone", () => {
    expect(t("site.status.portDown", { port: "<b>3000</b>" })).toBe("Port <b>3000</b> is not answering");
    expect(t("site.status.portDown")).toBe("Port {port} is not answering");
  });

  it("has no exclamation marks or Oops (plan section 7)", () => {
    for (const [k, v] of Object.entries(en)) {
      expect(v, k).not.toMatch(/!|\bOops\b/i);
    }
  });
});

describe("proxy target", () => {
  it("forwards to [::1] when the app listens on the IPv6 loopback only", async () => {
    const { proxyTarget } = await import("./status");
    expect(proxyTarget(3000, [{ port: 3000, process: "node.exe", loopback: true, ipv4: false, ipv6: true }])).toBe("[::1]:3000");
    expect(proxyTarget(3000, [{ port: 3000, process: "node.exe", loopback: true, ipv4: true, ipv6: true }])).toBe("127.0.0.1:3000");
    expect(proxyTarget(3000, undefined)).toBe("127.0.0.1:3000");
  });
});
