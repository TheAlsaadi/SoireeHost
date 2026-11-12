import { describe, expect, it } from "vitest";
import { versionLabel } from "./version";

describe("versionLabel", () => {
  it("shows a release version", () => {
    expect(versionLabel("1.2.3")).toBe("Version 1.2.3");
  });

  it("marks development builds", () => {
    expect(versionLabel("0.0.0-dev")).toBe("Version 0.0.0-dev (development build)");
  });

  it.each([undefined, null, 3, "", "1.2", "v1.2.3", "1.2.3<script>", "<img src=x onerror=alert(1)>"])(
    "refuses %p",
    (v) => {
      expect(versionLabel(v)).toBe("Version unknown");
    },
  );
});
