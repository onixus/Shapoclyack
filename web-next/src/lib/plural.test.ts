import { describe, expect, it } from "vitest";
import { pluralForm } from "@/lib/plural";

describe("pluralForm", () => {
  it("gives Russian its three forms, teens included", () => {
    expect(pluralForm(1, "ru")).toBe("one");
    expect(pluralForm(21, "ru")).toBe("one");
    // 11 is the trap: it ends in 1 and still takes the genitive plural.
    expect(pluralForm(11, "ru")).toBe("many");
    expect(pluralForm(2, "ru")).toBe("few");
    expect(pluralForm(24, "ru")).toBe("few");
    expect(pluralForm(12, "ru")).toBe("many");
    expect(pluralForm(5, "ru")).toBe("many");
    expect(pluralForm(0, "ru")).toBe("many");
  });

  it("gives English its two", () => {
    expect(pluralForm(1, "en")).toBe("one");
    expect(pluralForm(0, "en")).toBe("many");
    expect(pluralForm(2, "en")).toBe("many");
  });
});
