// @vitest-environment happy-dom
// The setup windows (ADR-0010) and the update sentences (ADR-0004).
import { flushSync, mount, unmount } from "svelte";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import SetupWindow from "./SetupWindow.svelte";
import { setApi, type Api, type SetupAction, type gui } from "../lib/api";
import { updateLine } from "../lib/setup";
import { t } from "../lib/i18n";

let ran: SetupAction[] = [];
let closed = 0;
let result: gui.SetupResult = { code: 0, cancelled: false };

function stubApi(): Api {
  const never = () => new Promise<never>(() => {});
  return new Proxy({} as Api, {
    get: (_t, prop) => {
      if (prop === "runSetup")
        return async (a: SetupAction) => {
          ran.push(a);
          return result;
        };
      if (prop === "closeSetup")
        return async () => {
          closed++;
        };
      if (prop === "openInstalled") return async () => {};
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

function button(target: HTMLElement, name: string): HTMLButtonElement {
  const b = [...target.querySelectorAll("button")].find((x) => x.textContent?.includes(name));
  if (!b) throw new Error(`no button ${name}`);
  return b;
}

describe("setup windows (ADR-0010)", () => {
  let target: HTMLElement;
  let cmp: ReturnType<typeof mount> | undefined;

  beforeEach(() => {
    ran = [];
    closed = 0;
    result = { code: 0, cancelled: false };
    setApi(stubApi());
    target = document.createElement("div");
    document.body.append(target);
  });

  afterEach(() => {
    if (cmp) unmount(cmp);
    cmp = undefined;
    target.remove();
  });

  const show = (info: gui.SetupState) => {
    cmp = mount(SetupWindow, { target, props: { info } });
    flushSync();
  };

  it("lists every change before installing, and installs only on the button", async () => {
    show({ mode: "not_installed", installed_version: "", this_version: "1.3.0", newer: true });
    expect(target.querySelectorAll(".confirm-list li")).toHaveLength(6);
    expect(target.textContent).toContain(t("setup.change.firewall"));
    expect(ran).toEqual([]);
    button(target, t("setup.install.go")).click();
    await settle();
    expect(ran).toEqual(["install"]);
    expect(target.textContent).toContain(t("setup.install.done"));
    // the installed control panel opens only once this window closes
    // (owner's VM check, 20 Nov 2026)
    expect(closed).toBe(1);
  });

  it("says nothing changed when the Windows prompt is declined", async () => {
    result = { code: 0, cancelled: true };
    show({ mode: "not_installed", installed_version: "", this_version: "1.3.0", newer: true });
    button(target, t("setup.install.go")).click();
    await settle();
    expect(target.querySelector('[role="alert"]')?.textContent).toContain(t("setup.cancelled"));
    expect(closed).toBe(0);
  });

  it("keeps settings unless the box is ticked (owner decision, 16 Nov 2026)", async () => {
    show({ mode: "uninstall", installed_version: "1.3.0", this_version: "1.3.0", newer: false });
    const box = target.querySelector<HTMLInputElement>('input[type="checkbox"]');
    expect(box?.checked).toBe(false);
    // the help sentence is read with the box (accessibility review, 21 Nov 2026)
    const help = document.getElementById(box?.getAttribute("aria-describedby") ?? "");
    expect(help?.textContent).toBe(t("setup.uninstall.purgeHelp"));
    button(target, t("setup.uninstall.go")).click();
    await settle();
    expect(ran).toEqual(["uninstall"]);
    // after an uninstall the window stays, to say a file goes at restart
    expect(closed).toBe(0);
    // and keyboard focus lands on Close instead of falling to the page
    expect(document.activeElement?.textContent).toBe(t("setup.close"));
  });

  it("removes settings too when the box is ticked", async () => {
    show({ mode: "uninstall", installed_version: "1.3.0", this_version: "1.3.0", newer: false });
    target.querySelector<HTMLInputElement>('input[type="checkbox"]')?.click();
    flushSync();
    button(target, t("setup.uninstall.go")).click();
    await settle();
    expect(ran).toEqual(["uninstall-purge"]);
  });

  it("explains a kept data folder after uninstall", async () => {
    result = { code: 30, cancelled: false };
    show({ mode: "uninstall", installed_version: "1.3.0", this_version: "1.3.0", newer: false });
    button(target, t("setup.uninstall.go")).click();
    await settle();
    expect(target.textContent).toContain(t("setup.code.30"));
  });

  it("offers an upgrade only from a newer copy", () => {
    show({ mode: "other_copy", installed_version: "1.4.0", this_version: "1.3.0", newer: false });
    expect(target.textContent).toContain(t("setup.other.older"));
    expect([...target.querySelectorAll("button")].some((b) => b.textContent?.includes(t("setup.other.upgrade", { v: "1.3.0" })))).toBe(false);
  });

  it("upgrades from a newer copy", async () => {
    show({ mode: "other_copy", installed_version: "1.2.0", this_version: "1.3.0", newer: true });
    button(target, t("setup.other.upgrade", { v: "1.3.0" })).click();
    await settle();
    expect(ran).toEqual(["install"]);
    expect(closed).toBe(1);
  });
});

describe("update status sentences (ADR-0004)", () => {
  it("names each state without upstream text", () => {
    expect(updateLine({ state: "ready", version: "1.3.0" })).toBe(t("settings.update.ready", { v: "1.3.0" }));
    expect(updateLine({ state: "failed", problem: "bad_signature" })).toBe(t("settings.update.refused"));
    expect(updateLine({ state: "failed", problem: "network" })).toBe(t("settings.update.network"));
    expect(updateLine({ state: "failed", problem: "<script>" })).toBe(t("settings.update.failed"));
    expect(updateLine({ state: "off", problem: "development_build" })).toBe(t("settings.update.dev"));
    expect(updateLine({ state: "off" })).toBe(t("settings.update.off"));
    expect(updateLine({ state: "idle" })).toBe(t("settings.update.never"));
    expect(updateLine(undefined)).toBe(t("settings.update.never"));
  });
});
