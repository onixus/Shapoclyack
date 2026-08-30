"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { fetchSsoStatus } from "@/lib/api";
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
 */
export function SsoSignInButton() {
  const t = useT();
  const [loginUrl, setLoginUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void fetchSsoStatus().then((status) => {
      if (!cancelled && status.enabled) setLoginUrl(status.login_url);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!loginUrl) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-xs uppercase tracking-wider text-slate-500">
        <span className="h-px flex-1 bg-slate-700" />
        {t("login.or")}
        <span className="h-px flex-1 bg-slate-700" />
      </div>
      <Button
        type="button"
        variant="outline"
        className="w-full border-slate-700 bg-slate-950 text-slate-100"
        // A full navigation, not a fetch: the provider answers with its own
        // login page, and an XHR cannot show it to the user.
        onClick={() => {
          window.location.href = loginUrl;
        }}
      >
        {t("login.sso")}
      </Button>
    </div>
  );
}
