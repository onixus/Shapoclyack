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
  return numericClaimMs(token, "exp");
}

/** `iat` as epoch milliseconds, or `null` — when this access token was minted,
 * i.e. when the session was last extended. Same tolerance as the expiry. */
export function accessTokenIssuedAt(token: string | null | undefined): number | null {
  return numericClaimMs(token, "iat");
}

function numericClaimMs(token: string | null | undefined, claim: "exp" | "iat"): number | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const claims = JSON.parse(
      typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("utf-8"),
    ) as Record<string, unknown>;
    const value = claims[claim];
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    return value * 1000;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------ *
 * Silent refresh (#314)
 *
 * The access token now lives fifteen minutes and is renewed through
 * `POST /api/auth/refresh`, which rotates an httpOnly cookie this code never
 * sees. The one decision the console makes is *whether* to renew, and the
 * rule is: only if the person has touched the console since the current
 * token was minted. A tab left open on a dashboard polls the API every few
 * seconds; if polling alone renewed the session, the idle timeout
 * (`OCTO_SESSION_IDLE_MINUTES`) would never apply to exactly the console it
 * exists for. The server enforces the timeout regardless — this only keeps
 * the console from quietly defeating it.
 * ------------------------------------------------------------------------ */

/** A page load is somebody doing something, so the clock starts there: a
 * console reopened within the idle window renews on its first request instead
 * of sending the user to the login form. */
let lastActivityAt = Date.now();

/** Record user activity (pointer, key, wheel, touch). Cheap enough to call on
 * every event: it is one comparison and one assignment. */
export function noteActivity(at: number = Date.now()): void {
  if (at > lastActivityAt) lastActivityAt = at;
}

export function lastActivity(): number {
  return lastActivityAt;
}

/** Whether a silent refresh is allowed for `token`: the user has been active
 * since it was issued. A token with no readable `iat` (one minted before this
 * existed, or not a JWT) is given the benefit of the doubt — the server still
 * decides. */
export function activeSinceIssued(token: string | null | undefined, activityAt: number): boolean {
  const issuedAt = accessTokenIssuedAt(token);
  if (issuedAt === null) return true;
  return activityAt > issuedAt;
}

/** Whether it is time to renew ahead of expiry: inside the warning window, or
 * inside the second half of the token's life when that is shorter — so a
 * deployment with a five-minute token does not refresh on every tick. */
export function refreshDue(token: string | null | undefined, now: number): boolean {
  const expiry = accessTokenExpiry(token);
  if (expiry === null) return false;
  const issuedAt = accessTokenIssuedAt(token);
  const ahead =
    issuedAt === null ? SESSION_WARNING_MS : Math.min(SESSION_WARNING_MS, (expiry - issuedAt) / 2);
  return expiry - now <= ahead;
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
