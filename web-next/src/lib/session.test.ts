import { describe, expect, it } from "vitest";
import {
  SESSION_WARNING_MS,
  accessTokenExpiry,
  minutesLeft,
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
