import { describe, expect, it } from "vitest";
import { activeNavHref, canSee, NAV, NAV_GROUPS, visibleNavGroups } from "@/lib/config/nav";
import { en, ru } from "@/lib/i18n/messages";

describe("navigation groups", () => {
  it("has a translated label for every group and entry in both languages", () => {
    for (const group of NAV_GROUPS) {
      expect(en[group.labelKey]).toBeTruthy();
      expect(ru[group.labelKey]).toBeTruthy();
      for (const item of group.items) {
        expect(en[item.labelKey]).toBeTruthy();
        expect(ru[item.labelKey]).toBeTruthy();
        if (item.hintKey) {
          expect(en[item.hintKey]).toBeTruthy();
          expect(ru[item.hintKey]).toBeTruthy();
        }
      }
    }
  });

  it("keeps hrefs unique", () => {
    const hrefs = NAV.map((item) => item.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });

  it("separates the external and internal surfaces", () => {
    const external = NAV_GROUPS.find((g) => g.id === "external")!;
    const internal = NAV_GROUPS.find((g) => g.id === "internal")!;
    expect(external.items.map((i) => i.href)).toContain("/scans/external");
    expect(internal.items.map((i) => i.href)).toContain("/scans/internal");
    expect(internal.items.map((i) => i.href)).toContain("/agents");
    expect(external.items.map((i) => i.href)).toContain("/org-profile");
  });
});

describe("role gating", () => {
  it("hides operator and admin doors from a viewer", () => {
    const viewer = visibleNavGroups("viewer").flatMap((g) => g.items.map((i) => i.href));
    expect(viewer).not.toContain("/scans/external");
    expect(viewer).not.toContain("/agents");
    expect(viewer).not.toContain("/users");
    expect(viewer).toContain("/vulnerabilities");
    expect(viewer).toContain("/runs");
    expect(viewer).toContain("/system");
  });

  it("shows an operator the scanning pages but not administration secrets", () => {
    const operator = visibleNavGroups("operator").flatMap((g) => g.items.map((i) => i.href));
    expect(operator).toContain("/scans/internal");
    expect(operator).toContain("/tenants");
    expect(operator).not.toContain("/service-tokens");
    expect(operator).toContain("/integrations");
  });

  it("gates /service-tokens on the permission, not on the global role", () => {
    // docs/ui.md promises this page to a tenant admin and a token-admin, whose
    // *global* role is whatever it is — usually viewer. Gating on the global
    // role hid it from both, so the promise was false in the one direction it
    // was made in (#318).
    const tokenAdmin = visibleNavGroups("viewer", ["tenant.credential.manage"]).flatMap((g) =>
      g.items.map((i) => i.href),
    );
    expect(tokenAdmin).toContain("/service-tokens");

    // ...and a global admin who holds nothing in the selected tenant does not
    // get it, which is the other half: an empty list is an answer, not a gap.
    const elsewhere = visibleNavGroups("admin", []).flatMap((g) => g.items.map((i) => i.href));
    expect(elsewhere).not.toContain("/service-tokens");

    // No list at all is an API older than #318: fall back to the role the
    // entry used to be gated on rather than losing the page on upgrade.
    expect(canSee({ permission: "tenant.credential.manage" }, "admin")).toBe(true);
    expect(canSee({ permission: "tenant.credential.manage" }, "operator")).toBe(false);
  });

  it("shows an admin everything and drops empty groups for others", () => {
    const admin = visibleNavGroups("admin", [
      "tenant.credential.manage",
    ]).flatMap((g) => g.items.map((i) => i.href));
    expect(admin).toEqual(NAV.map((i) => i.href));
    expect(canSee({ minRole: "admin" }, undefined)).toBe(false);
    expect(canSee({}, undefined)).toBe(true);
  });
});

describe("activeNavHref", () => {
  it("lights only the deepest matching entry", () => {
    expect(activeNavHref("/scans/external")).toBe("/scans/external");
    expect(activeNavHref("/scans")).toBe("/scans");
    expect(activeNavHref("/scans/internal?launch=1".split("?")[0])).toBe("/scans/internal");
    expect(activeNavHref("/runs/view")).toBe("/runs");
    expect(activeNavHref("/")).toBe("/");
    expect(activeNavHref("/vulnerabilities/view")).toBe("/vulnerabilities");
  });

  it("maps the legacy /jobs route onto the scan-jobs entry", () => {
    expect(activeNavHref("/jobs")).toBe("/scans");
  });

  it("returns null for an unknown path rather than the dashboard", () => {
    expect(activeNavHref("/nowhere")).toBeNull();
  });
});
