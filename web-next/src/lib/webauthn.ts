/**
 * The browser half of a WebAuthn ceremony (#315).
 *
 * The API speaks the JSON form of the WebAuthn options and responses — binary
 * fields as base64url strings — and `navigator.credentials` speaks
 * ArrayBuffers. This module is the translation between the two and nothing
 * else: no key material passes through it that the browser did not produce,
 * and nothing here decides whether a response is valid. That is the server's
 * job, done with a real verifier.
 *
 * Written against the plain Credential Management API rather than a helper
 * library: the conversion is thirty lines, and the one thing a dependency
 * would add is another package on the login page.
 */

export type WebAuthnOptions = {
  challenge_id: string;
  public_key: Record<string, unknown>;
};

/** What `POST /auth/mfa/verify` takes as `webauthn`, and registration too. */
export type WebAuthnAnswer = {
  challenge_id: string;
  credential: Record<string, unknown>;
};

/** Whether this browser can run a ceremony at all. False on plain HTTP pages
 * other than localhost: the API only exists in a secure context. */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.create === "function"
  );
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type Descriptor = { id: string; type: string; transports?: string[] };

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return (list as Descriptor[]).map((item) => ({
    type: "public-key",
    id: base64urlToBuffer(item.id),
    transports: item.transports as AuthenticatorTransport[] | undefined,
  }));
}

/** `PublicKeyCredentialCreationOptions` from the API's JSON. */
export function creationOptionsFromJSON(
  json: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const user = json.user as { id: string; name: string; displayName: string };
  return {
    ...(json as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64urlToBuffer(String(json.challenge)),
    user: { ...user, id: base64urlToBuffer(user.id) },
    excludeCredentials: descriptors(json.excludeCredentials),
  };
}

/** `PublicKeyCredentialRequestOptions` from the API's JSON. */
export function requestOptionsFromJSON(
  json: Record<string, unknown>,
): PublicKeyCredentialRequestOptions {
  return {
    ...(json as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64urlToBuffer(String(json.challenge)),
    allowCredentials: descriptors(json.allowCredentials),
  };
}

/** The JSON form of a new credential, as the API's verifier reads it. */
export function registrationToJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports:
        typeof response.getTransports === "function" ? response.getTransports() : undefined,
    },
  };
}

/** The JSON form of an assertion, as the API's verifier reads it. */
export function assertionToJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
    },
  };
}

/** Ask the authenticator for a new credential. Rejects if the user cancels. */
export async function createKey(options: WebAuthnOptions): Promise<WebAuthnAnswer> {
  const credential = (await navigator.credentials.create({
    publicKey: creationOptionsFromJSON(options.public_key),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The security key returned nothing.");
  return { challenge_id: options.challenge_id, credential: registrationToJSON(credential) };
}

/** Ask the authenticator to sign the challenge. Rejects if the user cancels. */
export async function signWithKey(options: WebAuthnOptions): Promise<WebAuthnAnswer> {
  const credential = (await navigator.credentials.get({
    publicKey: requestOptionsFromJSON(options.public_key),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The security key returned nothing.");
  return { challenge_id: options.challenge_id, credential: assertionToJSON(credential) };
}
