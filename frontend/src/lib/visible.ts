// S-34: text from outside (paths, user agents, hostnames, rule messages,
// worker details) is shown as text only, and characters that could hide or
// reorder it are shown as visible markers instead of being applied: control
// characters, bidirectional overrides and isolates, zero-width and other
// format characters, and line or paragraph separators. A request cannot make
// a log line read differently from what it is.

/** One run of text: plain text, or one hidden character shown as a marker. */
export interface Segment {
  text: string;
  marker: boolean;
}

const hidden = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** The marker shown for a hidden character, for example "U+202E". */
export function markerFor(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}

/**
 * Splits text into plain runs and markers. If max is given, the visible
 * text is cut to about max characters and an ellipsis segment is added.
 */
export function segments(text: string, max?: number): Segment[] {
  const out: Segment[] = [];
  let run = "";
  let shown = 0;
  for (const ch of text) {
    if (max !== undefined && shown >= max) {
      if (run) out.push({ text: run, marker: false });
      out.push({ text: "…", marker: false });
      return out;
    }
    if (hidden.test(ch)) {
      if (run) out.push({ text: run, marker: false });
      run = "";
      out.push({ text: markerFor(ch), marker: true });
      shown += 6;
    } else {
      run += ch;
      shown++;
    }
  }
  if (run) out.push({ text: run, marker: false });
  return out;
}

/** The same text as one plain string, markers written out, for copying. */
export function visibleText(text: string, max?: number): string {
  return segments(text, max)
    .map((s) => (s.marker ? "[" + s.text + "]" : s.text))
    .join("");
}
