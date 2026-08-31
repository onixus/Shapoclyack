"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AppearanceControls } from "@/components/appearance-controls";
import { SsoSignInButton } from "@/components/sso-sign-in-button";
import { setAccessToken } from "@/lib/api";
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

  // An SSO callback lands here with the session in the URL *fragment*, which
  // browsers never send to a server and access logs never record. Store it and
  // clear the fragment before hydrating, so a reload or a shared URL does not
  // carry the token with it.
  useEffect(() => {
    const fragment = window.location.hash.startsWith("#")
      ? new URLSearchParams(window.location.hash.slice(1))
      : null;
    const token = fragment?.get("access_token");
    if (token) {
      setAccessToken(token);
      window.history.replaceState(null, "", window.location.pathname);
    }
    void hydrate();
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
        <SsoSignInButton />
      </section>
    </div>
  );
}
