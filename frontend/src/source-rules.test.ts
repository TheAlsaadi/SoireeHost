/// <reference types="node" />
// Checks over the UI's source that a linter does not cover (plan section 7,
// S-33, S-34):
// - every string in markup comes from the message catalogue;
// - CSS uses logical properties only, so a right-to-left layout stays
//   possible;
// - no inline style attribute (the CSP allows none) and no inline script;
// - nothing renders HTML from data, and no link leaves the app.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function files(dir: string, ext: string[]): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...files(p, ext));
    else if (ext.some((e) => name.endsWith(e))) out.push(p);
  }
  return out;
}

const svelteFiles = files("src", [".svelte"]);
const cssFiles = files("src", [".css"]);

/** The markup of a Svelte file: script and style blocks removed. */
function markup(src: string): string {
  return src.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "");
}

/** Markup with every {...} expression and every tag removed. */
function bareText(src: string): string {
  let out = "";
  let depth = 0;
  for (const ch of markup(src).replace(/<!--[\s\S]*?-->/g, "")) {
    if (ch === "{") depth++;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out.replace(/<[^>]*>/g, " ");
}

describe("message catalogue", () => {
  it.each(svelteFiles)("%s has no text outside the catalogue", (f) => {
    const text = bareText(readFileSync(f, "utf8"));
    expect(text.match(/[A-Za-z]{2,}/g) ?? []).toEqual([]);
  });

  it.each(svelteFiles)("%s has no literal text in labelling attributes", (f) => {
    const m = markup(readFileSync(f, "utf8")).match(/\b(aria-label|title|placeholder|alt)="[^"{]*[A-Za-z][^"]*"/g);
    expect(m ?? []).toEqual([]);
  });
});

describe("logical CSS properties", () => {
  const physical =
    /(^|[\s;{])(margin|padding|border)-(left|right)\b|(^|[\s;{])(left|right)\s*:|text-align\s*:\s*(left|right)|float\s*:\s*(left|right)|border-(top|bottom)-(left|right)-radius/m;
  it.each([...cssFiles, ...svelteFiles])("%s uses logical properties", (f) => {
    const src = readFileSync(f, "utf8");
    const raw = f.endsWith(".css") ? src : (src.match(/<style[\s\S]*?<\/style>/g) ?? []).join("\n");
    const css = raw.replace(/\/\*[\s\S]*?\*\//g, "");
    expect(physical.exec(css)?.[0] ?? null).toBeNull();
  });
});

describe("S-33 and S-34 in markup", () => {
  it.each(svelteFiles)("%s has no inline style, inline handler string or external link", (f) => {
    const m = markup(readFileSync(f, "utf8"));
    expect(m).not.toMatch(/\sstyle="/);
    expect(m).not.toMatch(/\son[a-z]+="/);
    expect(m).not.toMatch(/href="(https?:|javascript:)/i);
    expect(m).not.toMatch(/\bwml-/);
    expect(m).not.toMatch(/\{@html/);
    // outside data never reaches attributes through a spread
    if (f.includes("Activity")) expect(m).not.toMatch(/\{\.\.\./);
  });

  it("index.html carries a strict CSP and no inline script", () => {
    const html = readFileSync("index.html", "utf8");
    expect(html).toMatch(/default-src 'none'/);
    expect(html).not.toMatch(/unsafe-inline|unsafe-eval/);
    expect(html.match(/<script(?![^>]*\bsrc=)[^>]*>/g) ?? []).toEqual([]);
  });
});
