import { describe, expect, it } from "vitest";
import { blockNonFileDrop } from "./navlock";

function drag(types: string[]): DragEvent & { prevented: boolean } {
  const e = {
    prevented: false,
    dataTransfer: { types, dropEffect: "copy" },
    preventDefault() {
      this.prevented = true;
    },
  };
  return e as unknown as DragEvent & { prevented: boolean };
}

describe("drop navigation lock (S-33)", () => {
  it.each([["text/uri-list", "text/plain"], ["text/plain"], ["text/html"], []])("cancels a drop of %j", (...types) => {
    const e = drag(types);
    blockNonFileDrop(e);
    expect(e.prevented).toBe(true);
    expect(e.dataTransfer?.dropEffect).toBe("none");
  });

  it("leaves file drops to Wails", () => {
    const e = drag(["Files"]);
    blockNonFileDrop(e);
    expect(e.prevented).toBe(false);
  });
});
