import { describe, expect, it } from "vitest";
import {
  SESSION_WARNING_MS,
  accessTokenExpiry,
  activeSinceIssued,
  lastActivity,
  minutesLeft,
  noteActivity,
  refreshDue,
  sessionStatus,
} from "@/lib/session";

/** A token shaped like the API's, with only the claim this module reads. Signed
 * with nothing, because nothing here verifies a signature — the point of the
 * module is that it makes no security decision. */
function tokenWithExp(exp: unknown): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "HS256", kid: "abc" })}.${encode({ sub: "viewer", exp })}.signature`;
}

const NOW = Date.UTC(2026, 8, 9, 12, 0, 0);

describe("accessTokenExpiry", () => {
  it("reads exp as epoch milliseconds", () => {
    expect(accessTokenExpiry(tokenWithExp(1_800_000_000))).toBe(1_800_000_000_000);
  });

  it("returns null for anything it cannot read", () => {
    expect(accessTokenExpiry(null)).toBeNull();
    expect(accessTokenExpiry("")).toBeNull();
    expect(accessTokenExpiry("not-a-jwt")).toBeNull();
    expect(accessTokenExpiry("a.b.c")).toBeNull();
    // A token whose exp is a string, which is a shape the console must not
    // crash on and must not warn about either.
    expect(accessTokenExpiry(tokenWithExp("soon"))).toBeNull();
  });
});

describe("sessionStatus", () => {
  it("is active well before the end", () => {
    const token = tokenWithExp((NOW + 60 * 60_000) / 1000);
    expect(sessionStatus(token, NOW)).toEqual({ state: "active", msLeft: 60 * 60_000 });
  });

  it("starts warning exactly five minutes out", () => {
    const token = tokenWithExp((NOW + SESSION_WARNING_MS) / 1000);
    expect(sessionStatus(token, NOW).state).toBe("expiring");
    // One millisecond earlier in the session's life is still quiet.
    expect(sessionStatus(token, NOW - 1).state).toBe("active");
  });

  it("is expired once exp has passed", () => {
    const token = tokenWithExp((NOW - 1000) / 1000);
    expect(sessionStatus(token, NOW)).toEqual({ state: "expired", msLeft: 0 });
  });

  it("says nothing at all about a token it cannot read", () => {
    // The pre-#314 console had no idea when a session ended; a token with no
    // exp must leave it exactly there rather than warning on every render.
    expect(sessionStatus("not-a-jwt", NOW)).toEqual({ state: "unknown", msLeft: null });
  });
});

describe("minutesLeft", () => {
  it("rounds up, so any remaining time reads as at least one minute", () => {
    expect(minutesLeft(1)).toBe(1);
    expect(minutesLeft(60_000)).toBe(1);
    expect(minutesLeft(61_000)).toBe(2);
    expect(minutesLeft(0)).toBe(0);
    expect(minutesLeft(null)).toBe(0);
  });
});

/** A token carrying both claims silent refresh reads, in epoch milliseconds. */
function tokenIssued(iatMs: number, expMs: number): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "HS256" })}.${encode({ sub: "viewer", iat: iatMs / 1000, exp: expMs / 1000 })}.signature`;
}

describe("activeSinceIssued", () => {
  // The rule that keeps the idle timeout meaningful (#314): a console left
  // polling on its own must not renew its own session.
  it("allows a refresh only after activity newer than the token", () => {
    const token = tokenIssued(NOW, NOW + 15 * 60_000);
    expect(activeSinceIssued(token, NOW + 1)).toBe(true);
    expect(activeSinceIssued(token, NOW)).toBe(false);
    expect(activeSinceIssued(token, NOW - 60_000)).toBe(false);
  });

  it("leaves a token with no iat to the server", () => {
    expect(activeSinceIssued(tokenWithExp(NOW / 1000), 0)).toBe(true);
    expect(activeSinceIssued(null, 0)).toBe(true);
  });
});

describe("refreshDue", () => {
  it("renews inside the warning window of a fifteen-minute token", () => {
    const token = tokenIssued(NOW, NOW + 15 * 60_000);
    expect(refreshDue(token, NOW + 9 * 60_000)).toBe(false);
    expect(refreshDue(token, NOW + 10 * 60_000)).toBe(true);
    expect(refreshDue(token, NOW + 20 * 60_000)).toBe(true);
  });

  it("uses half the life of a token shorter than twice the window", () => {
    // Otherwise a four-minute token would be "due" from the moment it was
    // minted and the console would refresh on every tick.
    const token = tokenIssued(NOW, NOW + 4 * 60_000);
    expect(refreshDue(token, NOW + 60_000)).toBe(false);
    expect(refreshDue(token, NOW + 2 * 60_000)).toBe(true);
  });

  it("is never due for a token it cannot read", () => {
    expect(refreshDue("not-a-jwt", NOW)).toBe(false);
  });
});

describe("noteActivity", () => {
  it("only ever moves the clock forward", () => {
    const later = Date.now() + 60_000;
    noteActivity(later);
    noteActivity(later - 30_000);
    expect(lastActivity()).toBe(later);
  });
});
