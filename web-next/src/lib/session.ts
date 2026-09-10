/** How long the console session has left, read from the token itself (#314).
 *
 * The API used to answer 401 the instant a token expired and `api.ts` turned
 * that into a hard redirect to the login form — mid-form, mid-edit, with no
 * warning. The token already carries its own `exp`, so the console can say
 * "this is about to end" before the server says "it has".
 *
 * Reading the payload is *not* verifying it: nothing here is a security
 * decision. A tampered `exp` moves a banner and changes no access — the server
 * verifies the signature, the account, the generation and the denylist on
 * every request (`api/services/sessions.py`).
 */

/** Warn this long before the session ends. Five minutes is enough to finish a
 * form or copy an unsaved note somewhere, and short enough that the banner is
 * not part of the furniture. */
export const SESSION_WARNING_MS = 5 * 60 * 1000;

export type SessionState = "unknown" | "active" | "expiring" | "expired";

export type SessionStatus = {
  state: SessionState;
  /** Milliseconds until `exp`, or `null` when the token does not say. */
  msLeft: number | null;
};

/** `exp` as epoch milliseconds, or `null` for anything this cannot read.
 *
 * Deliberately tolerant: no token, a token that is not a JWT, a payload that is
 * not base64url JSON, or one with no numeric `exp` all come back `null`, which
 * the caller renders as "no warning" rather than as an error. A console that
 * broke on an unexpected token shape would be worse than one that simply does
 * not warn. */
export function accessTokenExpiry(token: string | null | undefined): number | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const claims = JSON.parse(
      typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("utf-8"),
    ) as { exp?: unknown };
    if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) return null;
    return claims.exp * 1000;
  } catch {
    return null;
  }
}

/** Where the session is, at `now`.
 *
 * `unknown` for a token with no readable expiry — the console shows nothing
 * and keeps behaving exactly as it did before this existed. */
export function sessionStatus(token: string | null | undefined, now: number): SessionStatus {
  const expiry = accessTokenExpiry(token);
  if (expiry === null) return { state: "unknown", msLeft: null };
  const msLeft = expiry - now;
  if (msLeft <= 0) return { state: "expired", msLeft: 0 };
  if (msLeft <= SESSION_WARNING_MS) return { state: "expiring", msLeft };
  return { state: "active", msLeft };
}

/** Whole minutes left, rounded up: "1 minute" while any of it remains. */
export function minutesLeft(msLeft: number | null): number {
  if (msLeft === null || msLeft <= 0) return 0;
  return Math.ceil(msLeft / 60_000);
}
