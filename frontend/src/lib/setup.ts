// Setup results and update states as sentences from the catalogue
// (ADR-0004, ADR-0010). Codes are setup's closed-set exit codes; a code this
// build does not know reads as a generic failure, never as a number.

import type { gui, ipc } from "./api";
import { t, type MessageKey } from "./i18n";
import { dateTime } from "./status";

const codeKeys: Record<number, MessageKey> = {
  1: "setup.code.1",
  2: "setup.code.2",
  10: "setup.code.10",
  11: "setup.code.11",
  12: "setup.code.12",
  13: "setup.code.13",
  14: "setup.code.14",
  20: "setup.code.20",
  21: "setup.code.21",
  22: "setup.code.22",
  30: "setup.code.30",
};

/** The sentence for a setup run that did not succeed. */
export function setupProblem(r: gui.SetupResult): string {
  if (r.cancelled) return t("setup.cancelled");
  return t(codeKeys[r.code] ?? "setup.code.1");
}

/** Whether a setup run succeeded. */
export function setupOK(r: gui.SetupResult): boolean {
  return !r.cancelled && r.code === 0;
}

/** The update check's state as one sentence for Settings. */
export function updateLine(u: ipc.UpdateStatus | undefined): string {
  if (!u) return t("settings.update.never");
  switch (u.state) {
    case "checking":
      return t("settings.update.checking");
    case "downloading":
      return t("settings.update.downloading", { v: u.version ?? "" });
    case "ready":
      return t("settings.update.ready", { v: u.version ?? "" });
    case "interrupted":
      return t("settings.update.interrupted");
    case "off":
      return u.problem === "development_build" ? t("settings.update.dev") : t("settings.update.off");
    case "failed":
      switch (u.problem) {
        case "network":
          return t("settings.update.network");
        case "no_keys":
          return t("settings.update.noKeys");
        case "bad_signature":
        case "unknown_key":
        case "malformed":
        case "too_large":
        case "wrong_release":
        case "artifact_mismatch":
          return t("settings.update.refused");
        default:
          return t("settings.update.failed");
      }
  }
  return u.last_check ? t("settings.update.idle", { date: dateTime(u.last_check) }) : t("settings.update.never");
}
