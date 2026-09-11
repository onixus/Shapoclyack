import { describe, expect, it } from "vitest";
import type { Me } from "@/lib/api";
import {
  can,
  canOperate,
  holdsGlobalRole,
  holdsPermission,
  isTenantAdmin,
  tenantRank,
  tenantRole,
} from "@/lib/authz";

/** A principal as `/auth/me` sends one: `role` is the account's, and
 * `tenant_role`/`permissions` are what it holds in the tenant the console is
 * scoped to. Same helper as `nav.test.ts`, because it is the same question. */
function principal(
  role: Me["role"],
  tenant_role?: string,
  permissions?: string[],
): Pick<Me, "role" | "tenant_role" | "permissions"> {
  return { role, tenant_role, permissions };
}

describe("tenantRole", () => {
  it("prefers the membership over the account", () => {
    expect(tenantRole(principal("viewer", "scan-operator"))).toBe("scan-operator");
  });

  it("falls back to the global role on an API older than #318, and to viewer with no user", () => {
    // An installation that sends no `tenant_role` used to render these pages
    // for the global role; answering `viewer` there would take them away on
    // upgrade.
    expect(tenantRole(principal("admin"))).toBe("admin");
    expect(tenantRole(null)).toBe("viewer");
    expect(tenantRole(undefined)).toBe("viewer");
  });
});

describe("tenantRank", () => {
  it("ranks every role the server does", () => {
    // The table is a hand copy of `api/core/permissions.py`, guarded against
    // drift by `tests/test_api_rbac_permissions.py`. What is pinned here is
    // the shape the console depends on: the specialist roles are read-only
    // and `scan-operator` is an operator.
    expect(tenantRank(principal("viewer", "viewer"))).toBe(1);
    expect(tenantRank(principal("viewer", "operator"))).toBe(2);
    expect(tenantRank(principal("viewer", "admin"))).toBe(3);
    expect(tenantRank(principal("viewer", "scan-operator"))).toBe(2);
    for (const readOnly of ["auditor", "scope-approver", "token-admin", "risk-approver"]) {
      expect(tenantRank(principal("viewer", readOnly))).toBe(1);
    }
    // `tenant_role` can carry it even though no membership grants it.
    expect(tenantRank(principal("admin", "platform-admin"))).toBe(3);
  });

  it("gives an unknown role the read-only rank, as `rank_for` does", () => {
    expect(tenantRank(principal("admin", "role-from-a-newer-server"))).toBe(1);
  });
});

describe("canOperate and isTenantAdmin", () => {
  it("asks about the tenant, not the account", () => {
    // The #318 defect in one line: globally a viewer, an operator here.
    expect(canOperate(principal("viewer", "scan-operator"))).toBe(true);
    expect(isTenantAdmin(principal("viewer", "admin"))).toBe(true);
    // And the mirror: a global admin who is only a viewer in this tenant gets
    // the tenant's answer, because `require_tenant` will.
    expect(canOperate(principal("admin", "viewer"))).toBe(false);
    expect(isTenantAdmin(principal("admin", "viewer"))).toBe(false);
  });

  it("keeps an admin out of nothing and a viewer out of everything", () => {
    expect(isTenantAdmin(principal("viewer", "operator"))).toBe(false);
    expect(canOperate(principal("viewer", "auditor"))).toBe(false);
    expect(canOperate(null)).toBe(false);
  });
});

describe("holdsPermission", () => {
  it("reads the list the API sent", () => {
    const auditor = principal("viewer", "auditor", ["audit.read", "scan_scope.read"]);
    expect(holdsPermission(auditor, "scan_scope.read")).toBe(true);
    expect(holdsPermission(auditor, "scan_scope.approve")).toBe(false);
  });

  it("answers the fallback when there is no list at all", () => {
    // No list means an API older than #318, not "holds nothing": a door gated
    // on a permission has to keep rendering for whoever it rendered for.
    const legacy = principal("admin");
    expect(holdsPermission(legacy, "tenant.credential.manage")).toBe(false);
    expect(holdsPermission(legacy, "tenant.credential.manage", true)).toBe(true);
    // An empty list is an answer, and the answer is no.
    expect(holdsPermission(principal("admin", "admin", []), "audit.read", true)).toBe(false);
  });
});

describe("holdsGlobalRole", () => {
  it("ignores the membership, because `require_role` does", () => {
    // The cross-tenant listings resolve their own tenant set and gate on the
    // account, so a tenant admin who is globally a viewer gets a 403.
    expect(holdsGlobalRole(principal("viewer", "admin"), "operator")).toBe(false);
    expect(holdsGlobalRole(principal("operator", "viewer"), "operator")).toBe(true);
    expect(holdsGlobalRole(principal("admin", "viewer"), "admin")).toBe(true);
    expect(holdsGlobalRole(null, "viewer")).toBe(true);
  });
});

describe("can", () => {
  it("checks a named permission first, and falls back to the global admin with no list", () => {
    const tokenAdmin = principal("viewer", "token-admin", ["tenant.credential.manage"]);
    expect(can(tokenAdmin, { permission: "tenant.credential.manage" })).toBe(true);
    expect(can(tokenAdmin, { permission: "audit.read" })).toBe(false);
    expect(can(principal("admin"), { permission: "audit.read" })).toBe(true);
    expect(can(principal("operator"), { permission: "audit.read" })).toBe(false);
  });

  it("separates the global requirement from the tenant one", () => {
    const tenantAdmin = principal("viewer", "admin", []);
    // `/users` and `/tenants` hang off `require_role` on the account…
    expect(can(tenantAdmin, { globalMinRole: "admin" })).toBe(false);
    // …while everything `require_tenant` gates reads the membership.
    expect(can(tenantAdmin, { minRole: "admin" })).toBe(true);
    expect(can(principal("admin", "viewer", []), { minRole: "operator" })).toBe(false);
  });

  it("lets a door with no requirement through", () => {
    expect(can(principal("viewer", "viewer", []), {})).toBe(true);
  });

  it("reads an unknown `minRole` as read-only rather than as a locked door", () => {
    // A requirement naming a role this build does not know scores 1, so it
    // gates no tighter than `viewer` — a typo in a nav entry must not hide a
    // page from everybody without a word.
    expect(can(principal("viewer", "viewer", []), { minRole: "not-a-role" })).toBe(true);
  });
});
