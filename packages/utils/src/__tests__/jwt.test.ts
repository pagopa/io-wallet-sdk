import { describe, expect, it, vi } from "vitest";

import {
  JwtParseError,
  JwtVerificationError,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
} from "../index";

const compactJwt =
  "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IngiLCJ5IjoieSJ9fQ.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsImV4cCI6MjUyNDYwODAwMH0.signature";

const publicJwk = {
  crv: "P-256",
  kty: "EC",
  x: "x",
  y: "y",
};

const header = {
  alg: "ES256",
  jwk: publicJwk,
};

const signer = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk,
};

const verifyJwtCallback = vi.fn().mockResolvedValue({
  signerJwk: publicJwk,
  verified: true,
});

describe("jwt utilities", () => {
  it("decodes a compact JWT", () => {
    const decoded = decodeJwt({ jwt: compactJwt });

    expect(decoded).toMatchObject({
      compact: compactJwt,
      header,
      payload: {
        aud: "audience",
        exp: 2524608000,
        iss: "issuer",
      },
      signature: "signature",
    });
  });

  it("throws JwtParseError for malformed compact input", () => {
    expect(() => decodeJwt({ jwt: "not-a-jwt" })).toThrow(JwtParseError);
  });

  it("extracts jwk, did, and federation signers", () => {
    expect(
      jwtSignerFromJwt({
        header,
        payload: {},
      }),
    ).toStrictEqual(signer);

    expect(
      jwtSignerFromJwt({
        header: { alg: "ES256", kid: "#key-1" },
        payload: { iss: "did:example:123" },
      }),
    ).toStrictEqual({
      alg: "ES256",
      didUrl: "did:example:123#key-1",
      method: "did",
    });

    expect(
      jwtSignerFromJwt({
        header: {
          alg: "ES256",
          kid: "federation-key",
          trust_chain: ["trust-chain-jwt"],
        },
        payload: {},
      }),
    ).toStrictEqual({
      alg: "ES256",
      kid: "federation-key",
      method: "federation",
      trustChain: ["trust-chain-jwt"],
    });
  });

  it.each([
    ["expired", { exp: 1 }, {}],
    ["future nbf", { nbf: 2524608000 }, {}],
    ["wrong aud", { aud: "other" }, { expectedAudience: "audience" }],
    ["missing required claim", {}, { requiredClaims: ["iss" as const] }],
  ])("throws JwtVerificationError for %s JWT", async (_, payload, options) => {
    await expect(
      verifyJwt({
        compact: compactJwt,
        header,
        now: new Date("2025-01-01T00:00:00Z"),
        payload,
        signer,
        verifyJwtCallback,
        ...options,
      }),
    ).rejects.toThrow(JwtVerificationError);
  });
});
