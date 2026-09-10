"use client";

import { FormEvent, useState } from "react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { useStepUpStore } from "@/lib/step-up";

/**
 * "Enter a code to carry on", raised by the 403 the API answers a stale
 * second factor with (#315).
 *
 * Without it the console has no way to step up at all: the only other place
 * `verifyMfa` is called is the login form, so an admin whose last code is
 * sixteen minutes old would have to sign out and back in to issue a service
 * token. The set of operations behind step-up is wide enough — credentials,
 * scan scope, account administration — that this is the difference between a
 * control and an obstacle.
 *
 * The failed request is **not** replayed. It never reached the server, and
 * silently repeating a POST the user has not seen succeed is worse than asking
 * them to press the button again — which is what the dialog says.
 */
export function StepUpDialog() {
  const t = useT();
  const detail = useStepUpStore((state) => state.detail);
  const clear = useStepUpStore((state) => state.clear);
  const verifyMfa = useAuthStore((state) => state.verifyMfa);
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const supplied = code.trim();
    setSubmitting(true);
    setError(null);
    try {
      // Six digits are an authenticator code, anything else a recovery code —
      // the same split the security page makes, so nobody has to say which
      // kind of thing they are holding.
      const isTotp = /^\d{6}$/.test(supplied.replace(/\s/g, ""));
      await verifyMfa({ code: isTotp ? supplied : undefined, recoveryCode: isTotp ? undefined : supplied });
      toast.success(t("mfa.stepup.done"));
      setCode("");
      clear();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("login.failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog
      open={detail !== null}
      onOpenChange={(open) => {
        if (!open) {
          setCode("");
          setError(null);
          clear();
        }
      }}
    >
      <DialogContent>
        <form onSubmit={onSubmit}>
          <DialogHeader>
            <DialogTitle>{t("mfa.stepup.title")}</DialogTitle>
            <DialogDescription>{t("mfa.stepup.description")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5 py-4">
            <Label htmlFor="step-up-code">{t("mfa.disable.code")}</Label>
            <Input
              id="step-up-code"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              required
            />
            {error ? (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="submit" disabled={submitting}>
              {submitting ? t("login.mfa.submitting") : t("login.mfa.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
