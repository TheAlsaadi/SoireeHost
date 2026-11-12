// Proves the S-34 lint rules are active: if someone weakens eslint.config.js,
// this test fails instead of the rule silently disappearing.
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

// Runs from frontend/ (vitest's root), so it loads the project's eslint.config.js.
const eslint = new ESLint();

async function ruleIds(code: string, filePath: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath });
  return (result?.messages ?? []).map((m) => m.ruleId ?? "parse-error");
}

describe("S-34 lint rules", () => {
  it("rejects {@html} in Svelte", async () => {
    const ids = await ruleIds('<script lang="ts">let x = $state("");</script>\n{@html x}\n', "src/Probe.svelte");
    expect(ids).toContain("svelte/no-at-html-tags");
  });

  it.each([
    "el.innerHTML = data;",
    "el.outerHTML = data;",
    'el.insertAdjacentHTML("beforeend", data);',
    "document.write(data);",
    'new DOMParser().parseFromString(data, "text/html");',
    "document.createRange().createContextualFragment(data);",
  ])("rejects %s", async (stmt) => {
    const code = `export function f(el: HTMLElement, data: string): void { ${stmt} }\n`;
    const ids = await ruleIds(code, "src/probe.ts");
    expect(ids.some((id) => id === "no-restricted-properties" || id === "no-restricted-syntax")).toBe(true);
  });

  it("accepts textContent", async () => {
    const ids = await ruleIds("export function f(el: HTMLElement, data: string): void { el.textContent = data; }\n", "src/probe.ts");
    expect(ids).toEqual([]);
  });
});
