import type { Me, Role } from "@/lib/api";

/**
 * "May this principal do this?" — asked once, in one place (#318).
 *
 * The console used to answer it three different ways at about fifteen call
 * sites: `user.role === "admin"`, a rank comparison against `user.role`, and
 * (since #318) a permission lookup. The first two read the **global** role
 * from the JWT, which stopped being the answer the moment authority moved
 * into the membership: an account whose tenant role is `scan-operator` is
 * globally a `viewer`, the API serves it `GET /api/jobs`, and the console hid
 * Scan jobs, External/Internal scans, Agents and Schedules from it. Each page
 * that noticed was fixed on its own, which is why this file exists — a fix
 * per page is a defect per page not yet written.
 *
 * All of this is **presentation only**. The API is the boundary and enforces
 * every one of these on the request itself; what is decided here is whether a
 * door is worth showing.
 */

/** What a requirement is asked about: whatever `/auth/me` last said. */
export type Principal = Pick<Me, "role" | "tenant_role" | "permissions"> | null | undefined;

/**
 * Mirror of the rank column in `api/core/permissions.py`. The
 * separation-of-duties roles are rank 1 on purpose — a `scope-approver` at
 * rank 2 would pass every operator gate in the API — and `scan-operator` is
 * the one new role at rank 2, because it is an operator.
 *
 * `platform-admin` is here because `tenant_role` can carry it, not because it
 * is grantable on a membership.
 *
 * A copy, and deliberately so: `GET /api/rbac/roles` publishes `rank`, but it
 * is gated on `tenant.member.read`, which only the tenant admin holds — the
 * principals whose menu this decides cannot read the catalogue, so the console
 * would need a built-in table regardless. What a copy must not do is drift, so
 * `tests/test_api_rbac_permissions.py` reads this table out of this file and
 * asserts it equals `BUILTIN_ROLES`: a ninth role added there and forgotten
 * here would score the unknown-role 1 and hide every scanning page from it —
 * this file's own defect, reopened by an addition.
 */
const ROLE_RANK: Record<string, number> = {
  viewer: 1,
  operator: 2,
  admin: 3,
  auditor: 1,
  "scan-operator": 2,
  "scope-approver": 1,
  "token-admin": 1,
  "risk-approver": 1,
  "platform-admin": 3,
};

/** Ranks of the three roles an *account* can hold, for `globalMinRole`. */
const GLOBAL_ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

/**
 * What one door needs. Exactly one of the three is meaningful per entry, and
 * they are checked in this order:
 *
 * - `permission` — a named permission in the active tenant, which is what
 *   anything gated by `require_permission` on the server needs;
 * - `globalMinRole` — the rank of the account's global role, for the handful
 *   of routes still gated by `require_role` on the `TokenUser` (the
 *   cross-tenant listings and the platform's user administration). Using the
 *   tenant role for these would show a door the API answers 403 on;
 * - `minRole` — the rank held **in the active tenant**, which is what
 *   `require_tenant` compares against.
 */
export type Requirement = {
  permission?: string;
  minRole?: string;
  globalMinRole?: Role;
};

/** The role this principal holds in the tenant the console is scoped to.
 *
 * `tenant_role` when the API sent one (#318) and the global role otherwise —
 * an installation older than #318 sends no tenant role at all, and answering
 * `viewer` there would take away pages that used to render.
 */
export function tenantRole(user: Principal): string {
  return user?.tenant_role ?? user?.role ?? "viewer";
}

/** Its rank; 1 (read-only) for a role this build does not know, matching
 * `api.core.permissions.rank_for`. */
export function tenantRank(user: Principal): number {
  return ROLE_RANK[tenantRole(user)] ?? 1;
}

/** Whether the principal holds one named permission in the active tenant.
 *
 * `fallback` is what to answer when the API sent no permission list at all —
 * an installation older than #318 — so a page gated on this keeps rendering
 * for whoever it used to render for instead of disappearing.
 */
export function holdsPermission(
  user: Principal,
  permission: string,
  fallback = false,
): boolean {
  if (!user?.permissions) return fallback;
  return user.permissions.includes(permission);
}

/** Whether the *account* is at least `minimum` globally. */
export function holdsGlobalRole(user: Principal, minimum: Role): boolean {
  return GLOBAL_ROLE_RANK[user?.role ?? "viewer"] >= GLOBAL_ROLE_RANK[minimum];
}

/** Operator-or-better **in the active tenant** — the rank `require_tenant`
 * gates the tenant-scoped writes on. */
export function canOperate(user: Principal): boolean {
  return tenantRank(user) >= ROLE_RANK.operator;
}

/** Administers *this tenant* — not the installation. `is_platform_admin` is a
 * separate question and the switcher already answers it. */
export function isTenantAdmin(user: Principal): boolean {
  return tenantRank(user) >= ROLE_RANK.admin;
}

/** The one gate. Everything above is a named shorthand for a call to this. */
export function can(user: Principal, requirement: Requirement): boolean {
  if (requirement.permission) {
    // No list at all means an API older than #318, which sends none: fall back
    // to the global role the door used to be gated on, so an upgrade in two
    // steps loses no page.
    return holdsPermission(user, requirement.permission, user?.role === "admin");
  }
  if (requirement.globalMinRole) return holdsGlobalRole(user, requirement.globalMinRole);
  if (requirement.minRole) return tenantRank(user) >= (ROLE_RANK[requirement.minRole] ?? 1);
  return true;
}
