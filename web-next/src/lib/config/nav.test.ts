import { describe, expect, it } from "vitest";
import type { Me } from "@/lib/api";
import { activeNavHref, canSee, NAV, NAV_GROUPS, visibleNavGroups } from "@/lib/config/nav";
import { en, ru } from "@/lib/i18n/messages";

/** A principal as `/auth/me` sends one. `role` is the *account's* role and
 * `tenant_role`/`permissions` are what it holds in the tenant the console is
 * scoped to — which since #318 is where the authority lives. */
function principal(
  role: Me["role"],
  tenantRole?: string,
  permissions?: string[],
): Pick<Me, "role" | "tenant_role" | "permissions"> {
  return { role, tenant_role: tenantRole, permissions };
}

/** The menu this principal is shown, flattened. */
function menu(user: Parameters<typeof visibleNavGroups>[0]): string[] {
  return visibleNavGroups(user).flatMap((group) => group.items.map((item) => item.href));
}

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
    const viewer = menu(principal("viewer", "viewer", []));
    expect(viewer).not.toContain("/scans/external");
    expect(viewer).not.toContain("/agents");
    expect(viewer).not.toContain("/users");
    expect(viewer).toContain("/vulnerabilities");
    expect(viewer).toContain("/runs");
    expect(viewer).toContain("/system");
  });

  it("shows an operator the scanning pages but not administration secrets", () => {
    const operator = menu(principal("operator", "operator", ["config.read", "scan.cancel"]));
    expect(operator).toContain("/scans/internal");
    expect(operator).toContain("/tenants");
    expect(operator).not.toContain("/service-tokens");
    expect(operator).toContain("/integrations");
  });

  it("opens the scanning doors for a membership role, with no global role behind it", () => {
    // The template this file exists for (#318). A `scan-operator` is globally
    // a viewer — the JWT says so — and the API serves it every tenant-scoped
    // operator route (`require_tenant(Role.operator)`, rank 2) in the tenant
    // the console is scoped to. Gating the menu on the global role hid the
    // five pages it is granted this role *for*, and each was fixed on its own
    // until the question was asked in one place.
    const scanOperator = menu(
      principal("viewer", "scan-operator", ["config.read", "scan.cancel"]),
    );
    for (const href of [
      "/scans",
      "/scans/external",
      "/scans/internal",
      "/agents",
      "/schedules",
      "/wordlists",
      "/integrations",
    ]) {
      expect(scanOperator).toContain(href);
    }
    // ...and only those. Widening the scope stays with `scope-approver`, and
    // the platform-level pages are not the tenant's to see.
    expect(scanOperator).not.toContain("/service-tokens");
    expect(scanOperator).not.toContain("/users");
    expect(scanOperator).not.toContain("/tenants");
  });

  it("gives the separation-of-duties roles their own page and nobody else's", () => {
    // Each of these is rank 1 — they pass no write gate in the API — so what
    // they see is exactly what their named permission opens.
    const auditor = menu(
      principal("viewer", "auditor", [
        "audit.read",
        "config.read",
        "scan_scope.read",
        "tenant.quota.read",
      ]),
    );
    expect(auditor).toContain("/audit");
    expect(auditor).not.toContain("/scans");
    expect(auditor).not.toContain("/schedules");

    const tokenAdmin = menu(principal("viewer", "token-admin", ["tenant.credential.manage"]));
    expect(tokenAdmin).toContain("/service-tokens");
    expect(tokenAdmin).not.toContain("/scans");
  });

  it("keeps the two platform pages on the account's own role", () => {
    // `/tenants` and `/users` hang off `require_role` on the TokenUser, not on
    // a membership: the tenant's own admin is answered 403 by both, so showing
    // them would be a door onto a refusal.
    const tenantAdmin = principal("viewer", "admin", [
      "audit.read",
      "tenant.member.manage",
      "tenant.credential.manage",
    ]);
    expect(menu(tenantAdmin)).not.toContain("/users");
    expect(menu(tenantAdmin)).not.toContain("/tenants");
    // ...while the platform admin, whose *account* carries the role, keeps
    // both even in a tenant where it holds no membership.
    expect(menu(principal("admin", "admin", []))).toContain("/users");
    expect(menu(principal("operator", "viewer", []))).toContain("/tenants");
  });

  it("gates /service-tokens on the permission, not on the global role", () => {
    // docs/ui.md promises this page to a tenant admin and a token-admin, whose
    // *global* role is whatever it is — usually viewer. Gating on the global
    // role hid it from both, so the promise was false in the one direction it
    // was made in (#318).
    expect(menu(principal("viewer", "token-admin", ["tenant.credential.manage"]))).toContain(
      "/service-tokens",
    );

    // ...and a global admin who holds nothing in the selected tenant does not
    // get it, which is the other half: an empty list is an answer, not a gap.
    expect(menu(principal("admin", "viewer", []))).not.toContain("/service-tokens");

    // No list at all is an API older than #318: fall back to the role the
    // entry used to be gated on rather than losing the page on upgrade.
    expect(canSee({ permission: "tenant.credential.manage" }, principal("admin"))).toBe(true);
    expect(canSee({ permission: "tenant.credential.manage" }, principal("operator"))).toBe(false);
  });

  it("falls back to the global role when the API sends no tenant context", () => {
    // An installation older than #318 answers /auth/me with `role` alone.
    // Reading the tenant role as "viewer" there would take away every page
    // that used to render, on upgrade, for everybody.
    const legacyOperator = menu(principal("operator"));
    expect(legacyOperator).toContain("/scans");
    expect(legacyOperator).toContain("/schedules");
    expect(menu(principal("admin"))).toEqual(NAV.map((item) => item.href));
  });

  it("shows an admin everything and drops empty groups for others", () => {
    const admin = menu(principal("admin", "admin", ["tenant.credential.manage"]));
    expect(admin).toEqual(NAV.map((i) => i.href));
    expect(canSee({ globalMinRole: "admin" }, undefined)).toBe(false);
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
