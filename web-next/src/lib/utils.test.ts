import { describe, expect, it } from "vitest";
import { cn } from "@/lib/utils";

describe("cn", () => {
  it("keeps an APEX type style next to a text colour", () => {
    expect(cn("text-body-sm", "text-muted-foreground")).toBe("text-body-sm text-muted-foreground");
    expect(cn("text-h3 text-foreground")).toBe("text-h3 text-foreground");
  });

  it("still lets a later size win over an earlier one", () => {
    expect(cn("text-xs", "text-body-sm")).toBe("text-body-sm");
    expect(cn("text-body-sm", "text-sm")).toBe("text-sm");
  });
});
