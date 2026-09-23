"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { getAccessToken, refreshAccessToken } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import {
  activeSinceIssued,
  lastActivity,
  minutesLeft,
  noteActivity,
  refreshDue,
  sessionStatus,
} from "@/lib/session";
import { Button } from "@/components/ui/button";

/** How often the countdown is re-read. Fifteen seconds is fine for a banner
 * that only ever says whole minutes, and it costs nothing — the token is
 * already in memory and nothing is fetched. */
const TICK_MS = 15_000;

/** What counts as the user being at the console. Movement is included: reading
 * a long report without clicking is still using it. */
const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"] as const;

/** Keeps the console session alive while it is being used, and says so before
 * it ends when it is not (#314).
 *
 * Every tick, an access token inside its refresh window is renewed silently —
 * if the user has touched the console since it was minted (`@/lib/session`).
 * A console nobody is using is left to run down, and this banner is what they
 * find when they come back: "ends in N minutes" with a button that renews it,
 * or "has ended" once the token is gone. The banner stays at zero rather than
 * vanishing, because at that moment nothing on screen has changed and the next
 * click would be a 401 that takes an open form with it.
 *
 * The button tries a refresh first in both states: the access token can be
 * gone while the session behind it is still inside the idle window, and
 * sending that user to the login form would be a lie about what happened. */
export function SessionExpiryBanner() {
  const t = useT();
  const router = useRouter();
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const onActivity = () => noteActivity();
    for (const name of ACTIVITY_EVENTS) {
      window.addEventListener(name, onActivity, { passive: true });
    }
    return () => {
      for (const name of ACTIVITY_EVENTS) window.removeEventListener(name, onActivity);
    };
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), TICK_MS);
    return () => window.clearInterval(timer);
  }, []);

  const token = user ? getAccessToken() : null;
  const renewNow =
    !!user && refreshDue(token, now) && activeSinceIssued(token, lastActivity());
  useEffect(() => {
    if (!renewNow) return;
    let current = true;
    // Only a success re-renders at once. A failure waits for the next tick:
    // re-rendering on it would find the same token still due and fire again
    // straight away, which is a refresh loop against an API that is down.
    void refreshAccessToken().then((renewed) => {
      if (renewed && current) setNow(Date.now());
    });
    return () => {
      current = false;
    };
  }, [renewNow, now]);

  if (!user) return null;
  const status = sessionStatus(token, now);
  const expired = status.state === "expired";
  if (renewNow || (status.state !== "expiring" && !expired)) return null;

  async function stayOrSignIn() {
    noteActivity();
    if (await refreshAccessToken()) {
      setNow(Date.now());
      return;
    }
    // An expired token cannot be logged out — the server refuses it — so an
    // unconfirmed sign-out here is expected rather than worth a toast.
    const outcome = await logout();
    if (outcome === "uncertain" && !expired) toast.warning(t("session.logoutUncertain"));
    router.replace("/login");
  }

  return (
    <div
      role="status"
      className={
        expired
          ? "flex items-center justify-between gap-3 border-b border-rose-500/40 bg-rose-500/10 px-4 py-2 text-xs text-rose-900 dark:text-rose-200 md:px-6"
          : "flex items-center justify-between gap-3 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2 text-xs text-amber-900 dark:text-amber-200 md:px-6"
      }
    >
      <span>
        {expired
          ? t("session.expired")
          : t("session.expiringSoon", { minutes: minutesLeft(status.msLeft) })}
      </span>
      <Button type="button" size="sm" variant="outline" onClick={() => void stayOrSignIn()}>
        {expired ? t("session.signInAgain") : t("session.staySignedIn")}
      </Button>
    </div>
  );
}
