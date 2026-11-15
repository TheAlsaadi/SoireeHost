// Checks the built control panel in dist/ before it is embedded (S-33,
// ADR-0009). Runs after `vite build`; a failure stops the build.
//
// - The development-only fake supervisor is not in the bundle.
// - No file refers to a remote address (scripts, styles, fonts, images).
// - index.html has its CSP and loads only bundled scripts, none inline.
import { readdirSync, readFileSync, statSync } from "node:fs";
import process from "node:process";
import { join } from "node:path";

const root = "dist";
const problems = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else check(p);
  }
}

// Addresses that may appear as text inside the bundle without being loaded:
// the outside pages are opened by the Go side by name, never by address.
// Svelte and the Wails runtime carry links to their documentation inside
// error messages; they are text, never fetched.
const allowed = [
  /^https?:\/\/www\.w3\.org\//,
  /^http:\/\/127\.0\.0\.1:\d+$/,
  /^https:\/\/svelte\.dev\/e\/[a-z_]+$/,
  /^https:\/\/v3\.wails\.io\/learn\/build\/#using-a-browser-for-development$/,
];

function check(p) {
  if (!/\.(js|css|html|svg|json)$/.test(p)) return;
  const text = readFileSync(p, "utf8");
  if (text.includes("FAKE_SUPERVISOR_FOR_DEVELOPMENT_ONLY")) problems.push(`${p}: contains the development fake supervisor`);
  for (const m of text.matchAll(/https?:\/\/[^\s"'`)<>]+/g)) {
    if (!allowed.some((re) => re.test(m[0]))) problems.push(`${p}: refers to ${m[0]}`);
  }
  if (/\.css$/.test(p) && /@import\s+url|url\(\s*["']?(https?:|\/\/)/.test(text)) problems.push(`${p}: loads a remote stylesheet or font`);
}

walk(root);
const html = readFileSync(join(root, "index.html"), "utf8");
if (!/Content-Security-Policy/.test(html) || !/default-src 'none'/.test(html)) problems.push("index.html: CSP missing");
if (/unsafe-inline|unsafe-eval/.test(html)) problems.push("index.html: CSP allows inline content");
if (/<script(?![^>]*\bsrc=)[^>]*>/.test(html)) problems.push("index.html: inline script");
if (/\sstyle="/.test(html)) problems.push("index.html: inline style");

if (problems.length) {
  console.error("Bundle check failed:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log("Bundle check passed.");
