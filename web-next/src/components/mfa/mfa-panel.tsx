"use client";

import { FormEvent, useState } from "react";
import { ShieldCheck, ShieldOff, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { StatusBadge } from "@/components/status-badge";
import { CopyField } from "@/components/mfa/copy-field";
import { useConfirmTotp, useDisableMfa, useMfaStatus, useSetupTotp } from "@/hooks/use-mfa";
import { useAuthStore } from "@/lib/auth-store";
import { MFA_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { type MfaSetup } from "@/lib/api";

/**
 * The account's own second factor: enrol, confirm, keep the recovery codes,
 * turn it off (#315).
 *
 * Two things are shown exactly once and never fetched again, because the API
 * only ever hands them over once: the shared secret at setup, and the ten
 * recovery codes at confirmation. Both live in component state and nowhere
 * else — not in the query cache, not in a toast, not in localStorage — so
 * navigating away is what drops them, which is also what the copy says.
 *
 * The `otpauth://` link is rendered as text rather than as a QR image on
 * purpose: drawing the square would mean either a new dependency or handing an
 * external chart service the TOTP seed of every administrator on the
 * installation. Every authenticator worth using accepts a pasted link or a
 * typed secret.
 */
export function MfaPanel() {
  const t = useT();
  const role = useAuthStore((state) => state.user?.role ?? "viewer");
  const { data: status, isLoading, error } = useMfaStatus();
  const setup = useSetupTotp();
  const confirm = useConfirmTotp();
  const disable = useDisableMfa();

  const [enrolment, setEnrolment] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [disableCode, setDisableCode] = useState("");

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">{t("mfa.loading")}</p>;
  }
  if (error || !status) {
    return (
      <p className="text-sm text-destructive" role="alert">
        {error instanceof Error ? error.message : t("mfa.loading")}
      </p>
    );
  }

  const state = status.enabled ? "on" : status.setup_pending ? "pending" : "off";

  async function onStart() {
    try {
      setEnrolment(await setup.mutateAsync());
      setCode("");
    } catch {
      // The mutation toasts it. Nothing is half-started: the API either minted
      // a secret or did not, and without one there is no form to show.
    }
  }

  async function onConfirm(event: FormEvent) {
    event.preventDefault();
    try {
      const issued = await confirm.mutateAsync(code);
      // The order matters: the codes replace the enrolment form, so a user who
      // closes the panel here loses the codes and not the enrolment — which is
      // the state the "no codes left" hint below is written for.
      setRecoveryCodes(issued);
      setEnrolment(null);
      setCode("");
    } catch {
      // Wrong code: the form keeps the secret so the next attempt is a retype
      // of six digits rather than a re-scan.
    }
  }

  async function onDisable(event: FormEvent) {
    event.preventDefault();
    const supplied = disableCode.trim();
    // One field for both kinds, split here: a recovery code carries a dash and
    // letters, an authenticator code is six digits. Asking the user which one
    // they are holding would be asking them to explain their own screen.
    const isTotp = /^\d{6}$/.test(supplied.replace(/\s/g, ""));
    try {
      await disable.mutateAsync({
        password,
        code: isTotp ? supplied : undefined,
        recoveryCode: isTotp ? undefined : supplied,
      });
      setPassword("");
      setDisableCode("");
    } catch {
      // Reported by the mutation; the password field is cleared only on success
      // so a mistyped code does not cost the password as well.
    }
  }

  return (
    <section className="max-w-xl space-y-4 rounded-xl border border-border bg-card p-5">
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          {status.enabled ? (
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          ) : status.required ? (
            <ShieldAlert className="h-4 w-4 text-amber-500" />
          ) : (
            <ShieldOff className="h-4 w-4 text-muted-foreground" />
          )}
          <h2 className="text-lg font-semibold text-foreground">{t("mfa.title")}</h2>
          <StatusBadge value={state} map={MFA_STATUS} />
        </div>
        <p className="text-sm text-muted-foreground">{t("mfa.description")}</p>
      </div>

      <div className="space-y-1 text-sm text-muted-foreground">
        {status.enabled && status.enabled_at ? (
          <p>{t("mfa.enabledAt", { when: status.enabled_at.slice(0, 16).replace("T", " ") })}</p>
        ) : null}
        <p>
          {status.required ? t("mfa.requiredByPolicy", { role }) : t("mfa.optional")}
        </p>
        {status.enabled ? (
          <>
            <p>
              {status.recovery_codes_remaining > 0
                ? t("mfa.recoveryRemaining", { count: status.recovery_codes_remaining })
                : t("mfa.recoveryNoneLeft")}
            </p>
            <p>{t("mfa.stepupHint", { minutes: status.stepup_minutes })}</p>
          </>
        ) : null}
      </div>

      {recoveryCodes ? (
        <div
          role="alert"
          className="space-y-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4"
        >
          <h3 className="text-sm font-semibold text-foreground">{t("mfa.recovery.title")}</h3>
          <p className="text-xs text-muted-foreground">{t("mfa.recovery.description")}</p>
          <ul className="grid grid-cols-2 gap-1 font-mono text-sm text-foreground">
            {recoveryCodes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <div className="flex flex-wrap gap-2">
            <CopyField
              label={t("mfa.recovery.copyAll")}
              value={recoveryCodes.join("\n")}
              buttonOnly
            />
            <Button type="button" size="sm" onClick={() => setRecoveryCodes(null)}>
              {t("mfa.recovery.done")}
            </Button>
          </div>
        </div>
      ) : null}

      {enrolment ? (
        <form className="space-y-3 rounded-lg border border-border p-4" onSubmit={onConfirm}>
          <h3 className="text-sm font-semibold text-foreground">{t("mfa.setup.title")}</h3>
          <p className="text-xs text-muted-foreground">{t("mfa.setup.hint")}</p>
          <CopyField label={t("mfa.setup.uri")} value={enrolment.otpauth_uri} />
          <CopyField label={t("mfa.setup.secret")} value={enrolment.secret} />
          <p className="text-xs text-muted-foreground">
            {t("mfa.setup.params", {
              algorithm: enrolment.algorithm,
              digits: enrolment.digits,
              period: enrolment.period,
            })}
          </p>
          <div className="grid gap-1.5">
            <Label htmlFor="mfa-setup-code">{t("mfa.setup.code")}</Label>
            <Input
              id="mfa-setup-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              required
            />
          </div>
          <div className="flex gap-2">
            <Button type="submit" disabled={confirm.isPending}>
              {confirm.isPending ? t("mfa.setup.confirming") : t("mfa.setup.confirm")}
            </Button>
            <Button type="button" variant="outline" onClick={() => setEnrolment(null)}>
              {t("mfa.setup.cancel")}
            </Button>
          </div>
        </form>
      ) : null}

      {!status.enabled && !enrolment ? (
        <Button type="button" disabled={setup.isPending} onClick={() => void onStart()}>
          {setup.isPending
            ? t("mfa.action.starting")
            : status.setup_pending
              ? t("mfa.action.resume")
              : t("mfa.action.setUp")}
        </Button>
      ) : null}

      {status.enabled ? (
        <form className="space-y-3 border-t border-border pt-4" onSubmit={onDisable}>
          <h3 className="text-sm font-semibold text-foreground">{t("mfa.disable.title")}</h3>
          <p className="text-xs text-muted-foreground">{t("mfa.disable.description")}</p>
          <div className="grid gap-1.5">
            <Label htmlFor="mfa-disable-password">{t("mfa.disable.password")}</Label>
            <Input
              id="mfa-disable-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="mfa-disable-code">{t("mfa.disable.code")}</Label>
            <Input
              id="mfa-disable-code"
              autoComplete="one-time-code"
              value={disableCode}
              onChange={(event) => setDisableCode(event.target.value)}
              required
            />
          </div>
          <Button type="submit" variant="destructive" disabled={disable.isPending}>
            {disable.isPending ? t("mfa.disable.submitting") : t("mfa.disable.submit")}
          </Button>
        </form>
      ) : null}
    </section>
  );
}
