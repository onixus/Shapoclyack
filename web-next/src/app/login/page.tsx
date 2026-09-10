"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AppearanceControls } from "@/components/appearance-controls";
import { SsoSignInButton } from "@/components/sso-sign-in-button";
import { fetchSsoStatus, setAccessToken, type SsoStatus } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

/** An outstanding second factor: the challenge token, how long it is good for,
 * and the account it names when we know it — after an SSO redirect we do not,
 * and saying "viewer has MFA on" because that is what the form field happens
 * to hold would be a lie on the one screen that must not tell them. */
type Challenge = { token: string; expiresIn: number | null; username: string | null };

export default function LoginPage() {
  const router = useRouter();
  const { user, loading, hydrated, hydrate, login, verifyMfa } = useAuthStore();
  const t = useT();
  const [username, setUsername] = useState("viewer");
  const [password, setPassword] = useState("viewer-change-me");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // The second leg of a login (#315). Held here and nowhere else: it is not a
  // session, so it must not reach the token slot every request reads from.
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [sso, setSso] = useState<SsoStatus | null>(null);

  // An SSO callback lands here with the session in the URL *fragment*, which
  // browsers never send to a server and access logs never record. Store it and
  // clear the fragment before hydrating, so a reload or a shared URL does not
  // carry the token with it.
  //
  // An account that has enrolled a second factor gets `mfa_token` there
  // instead (#315): the identity provider proved an identity, not possession
  // of the authenticator. It goes into the same challenge state a password
  // login produces — never into the token slot — so the code step below is
  // what the user sees next.
  useEffect(() => {
    const fragment = window.location.hash.startsWith("#")
      ? new URLSearchParams(window.location.hash.slice(1))
      : null;
    const token = fragment?.get("access_token");
    const pending = fragment?.get("mfa_token");
    if (token || pending) {
      if (token) setAccessToken(token);
      window.history.replaceState(null, "", window.location.pathname);
    }
    if (pending) {
      const seconds = Number(fragment?.get("expires_in"));
      setChallenge({
        token: pending,
        expiresIn: Number.isFinite(seconds) ? seconds : null,
        username: null,
      });
      return;
    }
    void hydrate();
  }, [hydrate]);

  useEffect(() => {
    let cancelled = false;
    void fetchSsoStatus().then((status) => {
      if (!cancelled) setSso(status);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (hydrated && !loading && user) {
      // A session that owes an enrolment can reach one page. Landing it on the
      // dashboard would show it a screen of 403s instead (#315).
      router.replace(user.mfa_pending ? "/security" : "/");
    }
  }, [hydrated, loading, user, router]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const step = await login(username, password);
      if (step.status === "mfa-required") {
        setChallenge({ token: step.mfaToken, expiresIn: step.expiresIn, username });
        setCode("");
        return;
      }
      router.replace(step.mfaPending ? "/security" : "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("login.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function onVerify(event: FormEvent) {
    event.preventDefault();
    if (!challenge) return;
    setSubmitting(true);
    setError(null);
    try {
      await verifyMfa({
        mfaToken: challenge.token,
        code: useRecovery ? undefined : code,
        recoveryCode: useRecovery ? code : undefined,
      });
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("login.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  /** Back to the password form, dropping the challenge rather than reusing it. */
  function restart() {
    setChallenge(null);
    setCode("");
    setUseRecovery(false);
    setError(null);
  }

  // What the installation says about password sign-in (#315). Only ever a mode
  // — the break-glass account names stay on the server — so this is a notice
  // above the form, not a reason to hide it: a break-glass operator still has
  // to be able to type into it.
  const localLogin = sso?.enabled ? sso.local_login : "enabled";

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
          <h1 className="text-2xl font-semibold tracking-tight">
            {challenge ? t("login.mfa.title") : t("login.title")}
          </h1>
          <p className="text-sm text-slate-400">
            {!challenge
              ? t("login.subtitle")
              : challenge.username
                ? t("login.mfa.subtitle", { username: challenge.username })
                : t("login.mfa.subtitleAnon")}
          </p>
        </div>

        {challenge ? (
          <form className="space-y-4" onSubmit={onVerify}>
            <label className="grid gap-2 text-sm">
              {useRecovery ? t("login.mfa.recovery") : t("login.mfa.code")}
              <Input
                className="border-slate-700 bg-slate-950 text-slate-100"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode={useRecovery ? "text" : "numeric"}
                autoComplete="one-time-code"
                autoFocus
                required
              />
            </label>
            {error ? <p className="text-sm text-rose-400">{error}</p> : null}
            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? t("login.mfa.submitting") : t("login.mfa.submit")}
            </Button>
            <div className="flex items-center justify-between text-xs">
              <button
                type="button"
                className="text-sky-400 hover:underline"
                onClick={() => {
                  setUseRecovery((value) => !value);
                  setCode("");
                }}
              >
                {useRecovery ? t("login.mfa.useCode") : t("login.mfa.useRecovery")}
              </button>
              <button type="button" className="text-slate-400 hover:underline" onClick={restart}>
                {t("login.mfa.back")}
              </button>
            </div>
          </form>
        ) : (
          <>
            {localLogin === "disabled" ? (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
                {t("login.localDisabled")}
              </p>
            ) : null}
            {localLogin === "break-glass" ? (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
                {t("login.localBreakGlass")}
              </p>
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
            <SsoSignInButton status={sso} />
          </>
        )}
      </section>
    </div>
  );
}
