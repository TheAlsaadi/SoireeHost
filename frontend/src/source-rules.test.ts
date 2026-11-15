/// <reference types="node" />
// Checks over the UI's source that a linter does not cover (plan section 7,
// S-33, S-34):
// - every string in markup comes from the message catalogue;
// - CSS uses logical properties only, so a right-to-left layout stays
//   possible;
// - no inline style attribute (the CSP allows none) and no inline script;
// - nothing renders HTML from data, and no link leaves the app.
// Svelte files are read with the Svelte compiler's own parser and index.html
// with an HTML parser, never with regular expressions over markup.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse } from "svelte/compiler";
import { Window } from "happy-dom";
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

interface Node {
  type: string;
  [key: string]: unknown;
}

interface Attr {
  type: string;
  name?: string;
  value?: unknown;
}

// Keys of template nodes that hold JavaScript expressions or attributes,
// which the walk over markup text must not enter.
const notMarkup = new Set(["expression", "metadata", "context", "key", "index", "parameters", "test", "attributes", "name"]);

/** Visits every template node of a parsed Svelte file (not its scripts or style). */
function walk(n: unknown, visit: (node: Node) => void): void {
  if (Array.isArray(n)) {
    for (const x of n) walk(x, visit);
    return;
  }
  if (!n || typeof n !== "object") return;
  const node = n as Node;
  if (typeof node.type === "string") visit(node);
  for (const [k, v] of Object.entries(node)) {
    if (!notMarkup.has(k) && v && typeof v === "object") walk(v, visit);
  }
}

interface Parsed {
  text: string[];
  attrs: Attr[];
  htmlTags: number;
  css: string;
}

function parsed(f: string): Parsed {
  return parsedSource(readFileSync(f, "utf8"));
}

function parsedSource(src: string): Parsed {
  const ast = parse(src, { modern: true }) as unknown as {
    fragment: unknown;
    css?: { content?: { styles?: string } } | null;
  };
  const out: Parsed = { text: [], attrs: [], htmlTags: 0, css: ast.css?.content?.styles ?? "" };
  walk(ast.fragment, (node) => {
    if (node.type === "Text") out.text.push(String(node.data ?? ""));
    if (node.type === "HtmlTag") out.htmlTags++;
    if (Array.isArray(node.attributes)) out.attrs.push(...(node.attributes as Attr[]));
  });
  return out;
}

/** The literal text of an attribute value, without its {expressions}. */
function staticValue(a: Attr): string {
  if (!Array.isArray(a.value)) return "";
  return (a.value as Node[])
    .filter((v) => v.type === "Text")
    .map((v) => String(v.data ?? ""))
    .join("");
}

// The checks below must see what they look for: a probe with every
// violation, inside blocks and snippets, is caught.
describe("the source checks themselves", () => {
  it("find text, attributes, {@html} and styles in a probe", () => {
    const probe = [
      '<script lang="ts">let x = $state("Not markup"); const y = "<b>";</script>',
      "<!-- a comment is not text -->",
      "<div>Raw words</div>",
      '{#if x}<span title="Literal title" style="color: red" onclick="go()">{x}</span>{/if}',
      '{#each [1] as i (i)}<a href="https://example.com">{i}</a>{/each}',
      '{#snippet s()}<p wml-openurl="x" {...x}>{@html x}</p>{/snippet}',
      "<style>.a { margin-left: 1px; }</style>",
    ].join("\n");
    const p = parsedSource(probe);
    expect(p.text.join(" ")).toContain("Raw words");
    expect(p.text.join(" ")).not.toContain("Not markup");
    expect(p.text.join(" ")).not.toContain("comment");
    expect(p.htmlTags).toBe(1);
    const names = p.attrs.map((a) => a.name ?? a.type);
    expect(names).toEqual(expect.arrayContaining(["title", "style", "onclick", "href", "wml-openurl", "SpreadAttribute"]));
    expect(staticValue(p.attrs.find((a) => a.name === "title") as Attr)).toBe("Literal title");
    expect(p.css).toContain("margin-left");
  });
});

describe("message catalogue", () => {
  it.each(svelteFiles)("%s has no text outside the catalogue", (f) => {
    const text = parsed(f).text.join(" ");
    expect(text.match(/[A-Za-z]{2,}/g) ?? []).toEqual([]);
  });

  it.each(svelteFiles)("%s has no literal text in labelling attributes", (f) => {
    const bad = parsed(f)
      .attrs.filter((a) => a.type === "Attribute" && ["aria-label", "title", "placeholder", "alt"].includes(a.name ?? ""))
      .filter((a) => /[A-Za-z]/.test(staticValue(a)))
      .map((a) => `${a.name}="${staticValue(a)}"`);
    expect(bad).toEqual([]);
  });
});

describe("logical CSS properties", () => {
  const physical =
    /(^|[\s;{])(margin|padding|border)-(left|right)\b|(^|[\s;{])(left|right)\s*:|text-align\s*:\s*(left|right)|float\s*:\s*(left|right)|border-(top|bottom)-(left|right)-radius/m;
  it.each([...cssFiles, ...svelteFiles])("%s uses logical properties", (f) => {
    const raw = f.endsWith(".css") ? readFileSync(f, "utf8") : parsed(f).css;
    const css = raw.replace(/\/\*[\s\S]*?\*\//g, "");
    expect(physical.exec(css)?.[0] ?? null).toBeNull();
  });
});

describe("S-33 and S-34 in markup", () => {
  it.each(svelteFiles)("%s has no inline style, inline handler string or external link", (f) => {
    const p = parsed(f);
    expect(p.htmlTags, "{@html}").toBe(0);
    for (const a of p.attrs) {
      const name = (a.name ?? "").toLowerCase();
      if (a.type === "Attribute") {
        expect(name, "style attribute").not.toBe("style");
        expect(name.startsWith("on") && staticValue(a) !== "", `${name} given as a string`).toBe(false);
        expect(name === "href" && /^\s*(https?:|javascript:)/i.test(staticValue(a)), "external link").toBe(false);
      }
      expect(name.startsWith("wml-") || name.startsWith("data-wml-"), `${name} attribute`).toBe(false);
      // outside data never reaches attributes through a spread
      if (f.includes("Activity")) expect(a.type).not.toBe("SpreadAttribute");
    }
  });

  it("index.html carries a strict CSP and no inline script", () => {
    const window = new Window();
    const doc = window.document;
    doc.write(readFileSync("index.html", "utf8"));
    const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
    expect(doc.querySelectorAll("script:not([src])").length).toBe(0);
    expect(doc.querySelectorAll("[style]").length).toBe(0);
    void window.happyDOM.close();
  });
});
