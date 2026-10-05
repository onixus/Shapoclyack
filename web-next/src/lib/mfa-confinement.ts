/**
 * The two sentences the API opens its confinement 403 with
 * (`api/auth.py::_ENROLMENT_REQUIRED_DETAIL` and
 * `_PHISHING_RESISTANT_REQUIRED_DETAIL`): this session owes the installation
 * a second factor, or a security key, and may reach the MFA routes and
 * nothing else. Matched on the English detail for the reason `STEP_UP_MARKER`
 * is — the API has no error-code vocabulary — and pinned on the API side by
 * `tests/test_mfa_tenant_policy.py`.
 */
export const CONFINEMENT_MARKERS = [
  "This installation requires multi-factor authentication for your account",
  "This installation requires a security key (WebAuthn) for your account",
] as const;

/** Whether an error body is the confinement refusal rather than an ordinary 403. */
export function isConfinementRefusal(status: number | undefined, detail: unknown): boolean {
  return (
    status === 403 &&
    typeof detail === "string" &&
    CONFINEMENT_MARKERS.some((marker) => detail.startsWith(marker))
  );
}

let reread: (() => Promise<void>) | null = null;
let inFlight: Promise<void> | null = null;

/** Who re-reads the principal when a confinement refusal arrives. The auth
 * store registers itself here, so the axios interceptor can reach it without
 * `api.ts` importing anything that imports `api.ts`. */
export function onConfinement(handler: (() => Promise<void>) | null): void {
  reread = handler;
}

/**
 * A request came back confined (#504).
 *
 * Since #504 that can start in the middle of a session — a grant, a role
 * edit, a policy rollout — and the console read `/auth/me` only on hydrate
 * and on a tenant switch, so every panel turned into a raw 403 and the
 * enrolment banner did not appear until a reload. This re-reads the principal
 * once per burst: the refusals that arrive while a re-read is in flight join
 * it, and the handler itself does nothing once the principal already says
 * the session is confined, so the polls that keep failing ask nothing more.
 */
export function noteConfinement(): void {
  if (!reread || inFlight) return;
  inFlight = reread()
    .catch(() => {
      // Fail-soft: the refusal itself still reaches its caller, and the next
      // one tries again. A failed re-read must not become a second error on
      // top of the 403 the page is already showing.
    })
    .finally(() => {
      inFlight = null;
    });
}
