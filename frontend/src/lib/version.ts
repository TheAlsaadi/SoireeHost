import { t } from "./i18n";

// Turns the version reported by the Go side into the label shown in the window.
// The value crosses a process boundary, so it is checked, never trusted.
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;

export function versionLabel(v: unknown): string {
  if (typeof v !== "string" || !semver.test(v)) {
    return t("version.unknown");
  }
  if (v.endsWith("-dev")) {
    return t("version.dev", { v });
  }
  return t("version.release", { v });
}
