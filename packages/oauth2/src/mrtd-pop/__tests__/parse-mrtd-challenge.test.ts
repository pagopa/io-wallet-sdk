import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MrtdPopError } from "../../errors";
import { parseMrtdChallenge } from "../parse-mrtd-challenge";

function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const h = Base64.encode(JSON.stringify(header), true);
  const p = Base64.encode(JSON.stringify(payload), true);
  return `${h}.${p}.test-signature`;
}

const validHeader = {
  alg: "ES256",
  kid: "key-1",
  typ: "mrtd-ias+jwt",
};

const validPayload = {
  aud: "https://wallet.example.com",
  exp: 1700000000,
  htm: "POST",
  htu: "https://pid-provider.example.com/edoc-proof/init",
  iat: 1699999000,
  iss: "https://pid-provider.example.com",
  mrtd_auth_session: "session-123",
  mrtd_pop_jwt_nonce: "nonce-456",
  state: "state-789",
  status: "require_interaction",
  type: "mrtd+ias",
};

describe("parseMrtdChallenge", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should parse a valid challenge JWT from redirect URL", () => {
    const jwt = makeJwt(validHeader, validPayload);
    const redirectUrl = `https://wallet.example.com/callback?challenge_info=${encodeURIComponent(jwt)}`;

    const result = parseMrtdChallenge({ redirectUrl });

    expect(result.challengeJwt).toBe(jwt);
    expect(result.header).toEqual(expect.objectContaining(validHeader));
    expect(result.payload).toEqual(expect.objectContaining(validPayload));
  });

  it("should throw when challenge_info query parameter is missing", () => {
    const redirectUrl = "https://wallet.example.com/callback?other=value";

    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow(MrtdPopError);
    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow(
      "Missing 'challenge_info' query parameter",
    );
  });

  it("should throw when challenge_info is not a valid JWT format", () => {
    const redirectUrl =
      "https://wallet.example.com/callback?challenge_info=not-a-jwt";

    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow(MrtdPopError);
    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow(
      "Invalid JWT format",
    );
  });

  it("should throw when JWT header has wrong typ", () => {
    const jwt = makeJwt({ ...validHeader, typ: "jwt" }, validPayload);
    const redirectUrl = `https://wallet.example.com/callback?challenge_info=${encodeURIComponent(jwt)}`;

    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow();
  });

  it("should throw when JWT payload is missing required fields", () => {
    const incompletePayload = { ...validPayload, mrtd_auth_session: undefined };
    const jwt = makeJwt(validHeader, incompletePayload);
    const redirectUrl = `https://wallet.example.com/callback?challenge_info=${encodeURIComponent(jwt)}`;

    expect(() => parseMrtdChallenge({ redirectUrl })).toThrow();
  });

  it("should handle URL with additional query parameters", () => {
    const jwt = makeJwt(validHeader, validPayload);
    const redirectUrl = `https://wallet.example.com/callback?foo=bar&challenge_info=${encodeURIComponent(jwt)}&baz=qux`;

    const result = parseMrtdChallenge({ redirectUrl });

    expect(result.challengeJwt).toBe(jwt);
    expect(result.payload.mrtd_auth_session).toBe("session-123");
  });
});
