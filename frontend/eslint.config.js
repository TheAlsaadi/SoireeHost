// S-34: data from outside (hostnames, paths, user agents, log lines) must be
// rendered as text only. These rules fail the build if HTML is injected.
import js from "@eslint/js";
import svelte from "eslint-plugin-svelte";
import globals from "globals";
import ts from "typescript-eslint";

const noRawHtml = {
  "svelte/no-at-html-tags": "error",
  "no-restricted-properties": [
    "error",
    { property: "innerHTML", message: "S-34: render text with textContent or Svelte text bindings." },
    { property: "outerHTML", message: "S-34: render text with textContent or Svelte text bindings." },
    { property: "insertAdjacentHTML", message: "S-34: render text, never HTML." },
    { object: "document", property: "write", message: "S-34: render text, never HTML." },
    { object: "document", property: "writeln", message: "S-34: render text, never HTML." },
  ],
  "no-restricted-syntax": [
    "error",
    {
      selector: "NewExpression[callee.name='DOMParser']",
      message: "S-34: do not parse HTML from data.",
    },
    {
      selector: "CallExpression[callee.property.name='createContextualFragment']",
      message: "S-34: do not parse HTML from data.",
    },
  ],
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
};

export default ts.config(
  { ignores: ["dist/", "bindings/", "node_modules/"] },
  js.configs.recommended,
  ...ts.configs.recommended,
  ...svelte.configs.recommended,
  {
    languageOptions: { globals: { ...globals.browser } },
    rules: noRawHtml,
  },
  {
    files: ["**/*.svelte", "**/*.svelte.ts"],
    languageOptions: { parserOptions: { parser: ts.parser } },
  },
);
