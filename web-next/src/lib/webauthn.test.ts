import { afterEach, describe, expect, it, vi } from "vitest";
import {
  assertionToJSON,
  base64urlToBuffer,
  bufferToBase64url,
  creationOptionsFromJSON,
  isCancelledCeremony,
  requestOptionsFromJSON,
  signWithKey,
} from "@/lib/webauthn";

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("webauthn JSON ⇄ ArrayBuffer", () => {
  it("round-trips base64url without padding, including the URL-unsafe bytes", () => {
    // 0xfb 0xff encodes to "+/8" in plain base64 — exactly the characters
    // base64url replaces, so this is the case a naive atob/btoa would get wrong.
    const encoded = bufferToBase64url(bytes(0xfb, 0xff, 0x00));
    expect(encoded).toBe("-_8A");
    expect(new Uint8Array(base64urlToBuffer(encoded))).toEqual(new Uint8Array([0xfb, 0xff, 0x00]));
  });

  it("decodes the binary fields of creation options and leaves the rest alone", () => {
    const options = creationOptionsFromJSON({
      rp: { id: "console.example", name: "Shapoclyack" },
      user: { id: "AQID", name: "admin", displayName: "admin" },
      challenge: "BAUG",
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ id: "BwgJ", type: "public-key", transports: ["usb"] }],
    });
    expect(options.rp.id).toBe("console.example");
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([4, 5, 6]));
    expect(new Uint8Array(options.excludeCredentials![0].id as ArrayBuffer)).toEqual(
      new Uint8Array([7, 8, 9]),
    );
  });

  it("decodes the allow list the server names, so the browser offers the right key", () => {
    const options = requestOptionsFromJSON({
      rpId: "console.example",
      challenge: "BAUG",
      allowCredentials: [{ id: "BwgJ", type: "public-key" }],
    });
    expect(options.rpId).toBe("console.example");
    expect(new Uint8Array(options.allowCredentials![0].id as ArrayBuffer)).toEqual(
      new Uint8Array([7, 8, 9]),
    );
  });

  it("encodes an assertion the way the API's verifier reads it", () => {
    const json = assertionToJSON({
      id: "BwgJ",
      rawId: bytes(7, 8, 9),
      type: "public-key",
      response: {
        clientDataJSON: bytes(1),
        authenticatorData: bytes(2),
        signature: bytes(3),
        userHandle: null,
      },
    } as unknown as PublicKeyCredential);
    expect(json).toEqual({
      id: "BwgJ",
      rawId: "BwgJ",
      type: "public-key",
      response: {
        clientDataJSON: "AQ",
        authenticatorData: "Ag",
        signature: "Aw",
        userHandle: undefined,
      },
    });
  });

  it("recognises a cancelled or timed-out prompt, and nothing else", () => {
    expect(isCancelledCeremony(Object.assign(new Error("x"), { name: "NotAllowedError" }))).toBe(true);
    expect(isCancelledCeremony(Object.assign(new Error("x"), { name: "AbortError" }))).toBe(true);
    // A refused response from the API is an ordinary Error and must still be
    // shown as what it is.
    expect(isCancelledCeremony(new Error("that security key response is not valid"))).toBe(false);
    expect(isCancelledCeremony(null)).toBe(false);
  });

  it("signs with the browser and hands back the challenge id it was given", async () => {
    const get = vi.fn().mockResolvedValue({
      id: "BwgJ",
      rawId: bytes(7, 8, 9),
      type: "public-key",
      response: {
        clientDataJSON: bytes(1),
        authenticatorData: bytes(2),
        signature: bytes(3),
        userHandle: null,
      },
    });
    vi.stubGlobal("navigator", { credentials: { get } });

    const answer = await signWithKey({
      challenge_id: "c-1",
      public_key: { rpId: "console.example", challenge: "BAUG" },
    });

    expect(answer.challenge_id).toBe("c-1");
    expect((answer.credential as { rawId: string }).rawId).toBe("BwgJ");
    const publicKey = get.mock.calls[0][0].publicKey as PublicKeyCredentialRequestOptions;
    expect(new Uint8Array(publicKey.challenge as ArrayBuffer)).toEqual(new Uint8Array([4, 5, 6]));
  });
});
