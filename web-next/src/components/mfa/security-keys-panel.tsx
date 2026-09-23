"use client";

import { FormEvent, useState } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  useMfaStatus,
  useRegisterWebAuthnKey,
  useRevokeWebAuthnKey,
  useWebAuthnKeys,
} from "@/hooks/use-mfa";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { isCancelledCeremony, isWebAuthnSupported } from "@/lib/webauthn";

function when(value: string | null): string {
  return value ? value.slice(0, 16).replace("T", " ") : "";
}

/**
 * The account's security keys and passkeys: inventory, add, remove (#315).
 *
 * Rendered under the authenticator panel and only when the installation has a
 * WebAuthn relying party configured — an API that cannot run a ceremony has
 * nothing to offer here, and a button that always answers 409 is worse than
 * no button.
 *
 * A key is added on top of the authenticator app, so until that is enrolled
 * this panel says so instead of offering the button. Adding a key needs a
 * recent verification; the API's 403 raises the same step-up prompt as every
 * other credential operation, and the user presses the button again after.
 *
 * A session confined by the key policy (`phishing_resistant_pending`) is
 * offered "verify with your key now" once it holds one: registering a key
 * does not by itself re-prove the session — a signature from the key does.
 */
export function SecurityKeysPanel() {
  const t = useT();
  const role = useAuthStore((state) => state.user?.role ?? "viewer");
  const confined = useAuthStore((state) => state.user?.phishing_resistant_pending ?? false);
  const verifyWithKey = useAuthStore((state) => state.verifyWithKey);
  const { data: status } = useMfaStatus();
  const ready = Boolean(status?.enabled && status?.webauthn_available);
  const { data: keys } = useWebAuthnKeys(ready);
  const register = useRegisterWebAuthnKey();
  const revoke = useRevokeWebAuthnKey();
  const [name, setName] = useState("");
  const [verifying, setVerifying] = useState(false);

  if (!status?.webauthn_available) return null;
  const supported = isWebAuthnSupported();

  async function onAdd(event: FormEvent) {
    event.preventDefault();
    try {
      await register.mutateAsync({ name: name.trim() });
      setName("");
    } catch (err) {
      // Toasted by the mutation, or raised as the step-up prompt — except a
      // cancelled browser prompt, which the mutation leaves to us so it can
      // be said in the console's language. The name stays for the retry.
      if (isCancelledCeremony(err)) toast.error(t("mfa.keys.cancelled"));
    }
  }

  async function onVerify() {
    setVerifying(true);
    try {
      await verifyWithKey();
      toast.success(t("mfa.keys.verified"));
    } catch (err) {
      toast.error(
        isCancelledCeremony(err)
          ? t("mfa.keys.cancelled")
          : err instanceof Error
            ? err.message
            : t("login.failed"),
      );
    } finally {
      setVerifying(false);
    }
  }

  return (
    <section className="max-w-xl space-y-4 rounded-xl border border-border bg-card p-5">
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-sky-500" />
          <h2 className="text-lg font-semibold text-foreground">{t("mfa.keys.title")}</h2>
        </div>
        <p className="text-sm text-muted-foreground">{t("mfa.keys.description")}</p>
      </div>

      <div className="space-y-1 text-sm text-muted-foreground">
        {status.phishing_resistant_required ? (
          <p>{t("mfa.keys.requiredByPolicy", { role })}</p>
        ) : null}
        {status.stepup_phishing_resistant ? <p>{t("mfa.keys.stepupByPolicy")}</p> : null}
        {!status.enabled ? <p>{t("mfa.keys.needsTotp")}</p> : null}
        {status.enabled && !supported ? <p role="alert">{t("mfa.keys.unsupported")}</p> : null}
      </div>

      {ready ? (
        <ul className="divide-y divide-border rounded-lg border border-border" aria-label={t("mfa.keys.title")}>
          {(keys ?? []).length === 0 ? (
            <li className="p-3 text-sm text-muted-foreground">{t("mfa.keys.none")}</li>
          ) : (
            (keys ?? []).map((key) => (
              <li key={key.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <div className="space-y-0.5">
                  <p className="text-sm font-medium text-foreground">{key.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {key.backed_up ? t("mfa.keys.passkey") : t("mfa.keys.deviceBound")} ·{" "}
                    {t("mfa.keys.added", { when: when(key.created_at) })} ·{" "}
                    {key.last_used_at
                      ? t("mfa.keys.lastUsed", { when: when(key.last_used_at) })
                      : t("mfa.keys.neverUsed")}
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={revoke.isPending}
                  onClick={() => void revoke.mutateAsync(key.id).catch(() => undefined)}
                >
                  {t("mfa.keys.remove")}
                </Button>
              </li>
            ))
          )}
        </ul>
      ) : null}

      {ready && supported && confined && (keys ?? []).length > 0 ? (
        <Button type="button" disabled={verifying} onClick={() => void onVerify()}>
          {verifying ? t("mfa.keys.verifying") : t("mfa.keys.verifyNow")}
        </Button>
      ) : null}

      {ready && supported ? (
        <form className="space-y-3 border-t border-border pt-4" onSubmit={onAdd}>
          <div className="grid gap-1.5">
            <Label htmlFor="webauthn-key-name">{t("mfa.keys.name")}</Label>
            <Input
              id="webauthn-key-name"
              value={name}
              maxLength={64}
              placeholder={t("mfa.keys.namePlaceholder")}
              onChange={(event) => setName(event.target.value)}
            />
          </div>
          <p className="text-xs text-muted-foreground">{t("mfa.keys.addHint")}</p>
          <Button type="submit" variant="outline" disabled={register.isPending}>
            {register.isPending ? t("mfa.keys.adding") : t("mfa.keys.add")}
          </Button>
        </form>
      ) : null}
    </section>
  );
}
