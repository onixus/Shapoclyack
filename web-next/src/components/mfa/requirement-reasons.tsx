"use client";

import { useT } from "@/lib/i18n";
import { type MfaRequirementReason } from "@/lib/api";

/**
 * Why this account must carry a second factor (#504).
 *
 * The API computes the requirement from the global role *and* from what the
 * account holds in every tenant, and says where each part comes from. This
 * renders that list as given: the console never re-derives it from
 * `user.role`, which is what used to tell a tenant admin with a global
 * `viewer` role that MFA was "required for the viewer role" — or, before the
 * API counted tenants at all, optional.
 *
 * `phishingResistant` narrows it to the sources that ask for a security key.
 */
export function RequirementReasons({
  reasons,
  phishingResistant = false,
}: {
  reasons: MfaRequirementReason[] | undefined;
  phishingResistant?: boolean;
}) {
  const t = useT();
  const shown = (reasons ?? []).filter((reason) => !phishingResistant || reason.phishing_resistant);
  if (shown.length === 0) return null;
  return (
    <ul aria-label={t("mfa.reasons.label")} className="list-disc space-y-0.5 pl-5">
      {shown.map((reason) => {
        const source = reason.tenant_id
          ? t("mfa.reason.tenant", { role: reason.role, tenant: reason.tenant_id })
          : t("mfa.reason.global", { role: reason.role });
        return (
          <li key={`${reason.tenant_id ?? ""}:${reason.role}`}>
            {reason.permissions.length > 0
              ? t("mfa.reason.permissions", {
                  reason: source,
                  permissions: reason.permissions.join(", "),
                })
              : source}
          </li>
        );
      })}
    </ul>
  );
}
