"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { fetchSsoStatus, type SsoStatus } from "@/lib/api";
import { useT } from "@/lib/i18n";

/**
 * "Sign in with SSO", rendered only when the API says a provider is configured
 * (ROADMAP Track E).
 *
 * It renders nothing at all until the answer arrives, and nothing afterwards
 * if SSO is off: a button that leads to a 404 is worse than no button, and an
 * installation with no identity provider should not advertise one. The status
 * call cannot fail the page — `fetchSsoStatus` resolves to "off" on any error,
 * so password login keeps working when the API is older or unreachable.
 *
 * A caller that has already asked passes the answer in: the login page reads
 * the same status to decide what to say about password sign-in (#315), and
 * fetching it twice on one screen would be two calls for one fact.
 */
export function SsoSignInButton({
  status: given,
  onLdap,
}: { status?: SsoStatus | null; onLdap?: () => void } = {}) {
  const t = useT();
  const [fetched, setFetched] = useState<SsoStatus | null>(null);

  useEffect(() => {
    if (given !== undefined) return;
    let cancelled = false;
    void fetchSsoStatus().then((status) => {
      if (!cancelled) setFetched(status);
    });
    return () => {
      cancelled = true;
    };
  }, [given]);

  const status = given === undefined ? fetched : given;
  const providers = status?.providers?.length
    ? status.providers
    : status?.enabled
      ? [{ provider: "oidc" as const, login_url: status.login_url }]
      : [];

  if (!providers.length) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-xs uppercase tracking-wider text-muted-foreground">
        <span className="h-px flex-1 bg-border" />
        {t("login.or")}
        <span className="h-px flex-1 bg-border" />
      </div>
      {providers.map((provider) => (
        <Button
          key={provider.provider}
          type="button"
          variant="outline"
          className="w-full border-border bg-muted text-foreground"
          onClick={() => {
            if (provider.provider === "ldap") {
              onLdap?.();
            } else {
              // A full navigation: the IdP answers with its own login page.
              window.location.href = provider.login_url;
            }
          }}
        >
          {provider.provider === "saml"
            ? t("login.saml")
            : provider.provider === "ldap"
              ? t("login.ldap")
              : t("login.oidc")}
        </Button>
      ))}
    </div>
  );
}
