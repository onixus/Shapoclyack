"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AppearanceControls } from "@/components/appearance-controls";
import { fetchOIDCConfig, initiateOIDCLogin, OIDCConfig } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

export default function LoginPage() {
  const router = useRouter();
  const { user, loading, hydrated, hydrate, login } = useAuthStore();
  const t = useT();
  const [username, setUsername] = useState("viewer");
  const [password, setPassword] = useState("viewer-change-me");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [oidcConfig, setOidcConfig] = useState<OIDCConfig | null>(null);
  const [ssoLoading, setSsoLoading] = useState(false);

  useEffect(() => {
    void hydrate();
    fetchOIDCConfig()
      .then((cfg) => setOidcConfig(cfg))
      .catch(() => {
        // OIDC disabled or unreachable
      });
  }, [hydrate]);

  useEffect(() => {
    if (hydrated && !loading && user) {
      router.replace("/");
    }
  }, [hydrated, loading, user, router]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(username, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("login.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSSOLogin() {
    setSsoLoading(true);
    setError(null);
    try {
      const res = await initiateOIDCLogin("/");
      if (res.authorization_url) {
        window.location.href = res.authorization_url;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initiate SSO");
      setSsoLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-4">
      <div className="login-wash pointer-events-none absolute inset-0" aria-hidden />
      <div className="absolute right-4 top-4 z-20">
        <AppearanceControls />
      </div>
      <section className="relative z-10 w-full max-w-md space-y-6 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-slate-100 shadow-2xl backdrop-blur">
        <div className="space-y-2">
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-sky-400">
            {t("login.kicker")}
          </p>
          <h1 className="text-2xl font-semibold tracking-tight">{t("login.title")}</h1>
          <p className="text-sm text-slate-400">{t("login.subtitle")}</p>
        </div>

        {oidcConfig?.enabled ? (
          <div className="space-y-4">
            <Button
              type="button"
              variant="outline"
              className="w-full border-sky-600 bg-sky-950/40 text-sky-200 hover:bg-sky-900/60 hover:text-white"
              disabled={ssoLoading}
              onClick={handleSSOLogin}
            >
              {ssoLoading ? t("login.ssoConnecting") : t("login.sso")}
            </Button>
            <div className="relative flex items-center justify-center">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-slate-800" />
              </div>
              <span className="relative bg-slate-900 px-3 text-xs uppercase text-slate-400">
                {t("login.orDivider")}
              </span>
            </div>
          </div>
        ) : null}

        <form className="space-y-4" onSubmit={onSubmit}>
          <label className="grid gap-2 text-sm">
            {t("login.username")}
            <Input
              className="border-slate-700 bg-slate-950 text-slate-100"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label className="grid gap-2 text-sm">
            {t("login.password")}
            <Input
              className="border-slate-700 bg-slate-950 text-slate-100"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          {error ? <p className="text-sm text-rose-400">{error}</p> : null}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? t("login.submitting") : t("login.submit")}
          </Button>
        </form>
      </section>
    </div>
  );
}

