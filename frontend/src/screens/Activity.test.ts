// @vitest-environment happy-dom
// Phase 5 acceptance check (plan section 9, S-34): a request with script in
// its path and user agent shows as plain text in Activity. The real Activity
// screen is mounted with a stand-in supervisor whose access log holds the
// attack, the row is opened, and the test checks that the text appears
// literally and that no element, attribute or script came from it.
import { flushSync, mount, unmount } from "svelte";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Activity from "./Activity.svelte";
import { setApi, type Api, type ipc } from "../lib/api";
import { app } from "../lib/state.svelte";

const evilPath = "/<script>window.__pwned=1</script><img src=x onerror=\"window.__pwned=2\">";
const evilAgent = '<img src=x onerror="window.__pwned=3"><svg onload="window.__pwned=4"></svg> ' + String.fromCodePoint(0x202e) + "fdp.exe";
const evilRule = "<b>XSS</b> Attack Detected via libinjection";

const entry: ipc.AccessEntry = {
  time: new Date().toISOString(),
  method: "GET",
  host: "plain-river-tide.trycloudflare.com",
  uri: evilPath,
  status: 403,
  client_ip: "198.51.100.7",
  user_agent: evilAgent,
  size: 0,
  duration_ms: 1,
  site_id: "recipes",
  firewall: { action: "blocked", rules: [{ id: 941100, severity: "critical", msg: evilRule, where: ["REQUEST_FILENAME"] }] },
};

function stubApi(): Api {
  const never = () => new Promise<never>(() => {});
  return new Proxy({} as Api, {
    get: (_t, prop) => {
      if (prop === "activity") return async () => ({ entries: [entry], skipped: 0, more: false });
      if (prop === "onFolderDropped") return () => () => {};
      return never;
    },
  });
}

async function settle() {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
    flushSync();
  }
}

describe("Activity shows attacker text as text (S-34)", () => {
  let target: HTMLElement;
  let cmp: ReturnType<typeof mount> | undefined;

  beforeEach(() => {
    setApi(stubApi());
    app.config = { version: 1, listen: "127.0.0.1:8787", server: {} as never, tunnel: {} as never, sites: [] };
    target = document.createElement("div");
    document.body.append(target);
    (window as unknown as { __pwned?: number }).__pwned = 0;
  });

  afterEach(() => {
    if (cmp) unmount(cmp);
    target.remove();
  });

  it("renders the path, user agent and rule message literally", async () => {
    cmp = mount(Activity, { target });
    await settle();

    const row = target.querySelector("tbody tr");
    expect(row, "the request is listed").not.toBeNull();
    expect(row?.classList.contains("is-blocked")).toBe(true);
    expect(row?.textContent).toContain("Blocked");
    expect(row?.textContent).toContain("GET /<script>window.__pwned=1</script>");

    (row as HTMLElement).click();
    await settle();

    const path = target.querySelector('[data-testid="detail-path"]');
    const agent = target.querySelector('[data-testid="detail-agent"]');
    expect(path?.textContent).toBe(evilPath);
    // the right-to-left override is shown as a marker, not applied
    expect(agent?.textContent).toBe('<img src=x onerror="window.__pwned=3"><svg onload="window.__pwned=4"></svg> U+202Efdp.exe');
    expect(agent?.querySelector(".ctl")?.textContent).toBe("U+202E");
    expect(target.textContent).toContain(evilRule);

    // nothing from the request became markup
    expect(target.querySelectorAll("script, img, b, svg[onload], [onerror], [onload]").length).toBe(0);
    for (const el of target.querySelectorAll("*")) {
      for (const attr of el.getAttributeNames()) {
        expect(attr.startsWith("on"), `${el.tagName} has ${attr}`).toBe(false);
        expect(el.getAttribute(attr) ?? "").not.toContain("pwned");
      }
    }
    expect((window as unknown as { __pwned?: number }).__pwned).toBe(0);
  });
});
