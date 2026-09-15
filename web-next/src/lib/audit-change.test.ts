import { describe, expect, it } from "vitest";
import { brief, changeShape, changedFields } from "@/lib/audit-change";

describe("changedFields", () => {
  it("names only the fields that differ", () => {
    const rows = changedFields(
      { role: "viewer", enabled: true, note: "same" },
      { role: "operator", enabled: true, note: "same" },
    );
    expect(rows).toEqual([{ key: "role", from: "viewer", to: "operator" }]);
  });

  it("does not report an unchanged list as a change", () => {
    // The documents are decoded JSON, so two equal arrays are two different
    // objects: `===` would mark every list-valued field as changed on every
    // event, which is most of what a scope or permission edit contains.
    const rows = changedFields(
      { scope: ["10.0.0.0/8", "example.com"] },
      { scope: ["10.0.0.0/8", "example.com"] },
    );
    expect(rows).toEqual([]);
  });

  it("reports a field that appeared and one that went away", () => {
    const rows = changedFields({ old_only: 1 }, { new_only: 2 });
    expect(rows).toEqual([
      { key: "new_only", from: "∅", to: "2" },
      { key: "old_only", from: "1", to: "∅" },
    ]);
  });

  it("summarises nested values rather than spelling them out", () => {
    const rows = changedFields({ scope: ["a"] }, { scope: ["a", "b", "c"] });
    expect(rows).toEqual([{ key: "scope", from: "[1]", to: "[3]" }]);
  });

  it("survives a creation and a deletion, where one side is null", () => {
    expect(changedFields(null, { role: "admin" })).toEqual([
      { key: "role", from: "∅", to: "admin" },
    ]);
    expect(changedFields({ role: "admin" }, null)).toEqual([
      { key: "role", from: "admin", to: "∅" },
    ]);
    expect(changedFields(null, null)).toEqual([]);
  });
});

describe("brief", () => {
  it("clips a long value instead of letting it set the row height", () => {
    const long = "a".repeat(80);
    expect(brief(long)).toHaveLength(28);
    expect(brief(long).endsWith("…")).toBe(true);
  });

  it("distinguishes absent from empty", () => {
    expect(brief(null)).toBe("∅");
    expect(brief(undefined)).toBe("∅");
    expect(brief("")).toBe("");
    expect(brief(false)).toBe("false");
    expect(brief(0)).toBe("0");
  });
});

describe("changeShape", () => {
  it("says which side is missing, and nothing when both are there", () => {
    expect(changeShape(null, { a: 1 })).toBe("created");
    expect(changeShape({ a: 1 }, null)).toBe("removed");
    expect(changeShape({ a: 1 }, { a: 2 })).toBeNull();
    expect(changeShape(null, null)).toBeNull();
  });
});
