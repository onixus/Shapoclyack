import { describe, expect, it } from "vitest";
import { filterEntries, jumpEntries, type PaletteEntry } from "@/components/command-palette";
import { translate } from "@/lib/i18n";
import type { Translate } from "@/lib/i18n";

const t = ((key, vars) => translate("en", key, vars)) as Translate;
t.locale = "en";
t.label = (s: string) => s;

describe("jumpEntries", () => {
  it("recognises a run id and opens the run report", () => {
    const out = jumpEntries("20260909T101010Z", t);
    expect(out.map((e) => e.id)).toEqual(["run"]);
    expect(out[0].href).toBe("/runs/view?runId=20260909T101010Z");
  });

  it("recognises a job id and deep-links the drawer", () => {
    const out = jumpEntries("abc123def456", t);
    expect(out[0]).toMatchObject({ id: "job", href: "/scans?job=abc123def456" });
  });

  it("turns a CVE into a vulnerability search and an IP into an asset search", () => {
    expect(jumpEntries("CVE-2024-3094", t).map((e) => e.id)).toEqual(["search-vulns"]);
    expect(jumpEntries("10.0.0.7", t).map((e) => e.id)).toEqual(["search-assets"]);
    expect(jumpEntries("10.0.0.7", t)[0].href).toBe("/assets?q=10.0.0.7");
  });

  it("offers both searches for free text and nothing for blanks", () => {
    expect(jumpEntries("openssh", t).map((e) => e.id)).toEqual(["search-vulns", "search-assets"]);
    expect(jumpEntries("   ", t)).toEqual([]);
  });
});

describe("filterEntries", () => {
  const entries: PaletteEntry[] = [
    {
      id: "/vulnerabilities",
      group: "pages",
      label: "Vulnerabilities",
      href: "/vulnerabilities",
      keywords: "Risk",
    },
    {
      id: "/agents",
      group: "pages",
      label: "Agents",
      href: "/agents",
      hint: "Distributed worker fleet",
    },
  ];

  it("matches label, hint, keywords and path", () => {
    expect(filterEntries(entries, "risk").map((e) => e.id)).toEqual(["/vulnerabilities"]);
    expect(filterEntries(entries, "fleet").map((e) => e.id)).toEqual(["/agents"]);
    expect(filterEntries(entries, "/agen").map((e) => e.id)).toEqual(["/agents"]);
    expect(filterEntries(entries, "")).toHaveLength(2);
  });
});
