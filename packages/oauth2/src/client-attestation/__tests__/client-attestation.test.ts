/* eslint-disable max-lines-per-function */
import { Jwk, JwtSigner, decodeJwt } from "@openid4vc/oauth2";
import { encodeToBase64Url } from "@openid4vc/utils";
import { describe, expect, it, vi } from "vitest";

import { createClientAttestationJwt } from "../client-attestation";

describe("createClientAttestationJwt", () => {
  const mockJwk: Jwk = {
    crv: "P-256",
    kty: "EC",
    x: "mock-x-value",
    y: "mock-y-value",
  };

  const mockSigner: JwtSigner = {
    alg: "ES256",
    method: "jwk",
    publicJwk: mockJwk,
  };

  const mockSignJwt = vi.fn(async (_signer, { header, payload }) => ({
    jwt: [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join("."),
    signerJwk: mockJwk,
  }));

  const baseOptions = {
    authenticatorAssuranceLevel: "high",
    callbacks: { signJwt: mockSignJwt },
    clientId: "client-id-123",
    confirmation: { jwk: mockJwk },
    expiresAt: new Date(1700000000000 + 3600000),
    issuer: "https://issuer.example",
    signer: mockSigner,
    trustChain: ["trust-chain-value-1", "trust-chain-value-2"] as [
      string,
      ...string[],
    ],
  };

  it("should create a valid client attestation jwt", async () => {
    const jwt = await createClientAttestationJwt(baseOptions);

    expect(typeof jwt).toBe("string");
    expect(jwt.split(".").length).toBe(3);
    expect(mockSignJwt).toHaveBeenCalledTimes(1);

    const decoded = decodeJwt({ jwt });
    expect(decoded.header.typ).toBe("oauth-client-attestation+jwt");
    expect(decoded.header.alg).toBe("ES256");
    expect(decoded.header.trust_chain).toEqual([
      "trust-chain-value-1",
      "trust-chain-value-2",
    ]);
    expect(decoded.payload.sub).toBe("client-id-123");
    expect(decoded.payload.iss).toBe("https://issuer.example");
    expect(decoded.payload.aal).toBe("high");
    expect(decoded.payload.cnf).toEqual({ jwk: mockJwk });
    expect(decoded.payload.exp).toBe(1700003600);
  });

  it("should include issuedAt timestamp when provided", async () => {
    const issuedAt = new Date(1700000000000);
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      issuedAt,
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.iat).toBe(1700000000);
  });

  it("should include additionalPayload when provided", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      additionalPayload: {
        custom_claim: "custom-value",
        wallet_name: "Test Wallet",
      },
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.custom_claim).toBe("custom-value");
    expect(decoded.payload.wallet_name).toBe("Test Wallet");
  });

  it("should include optional wallet_link when provided in additionalPayload", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      additionalPayload: {
        wallet_link: "https://wallet.example",
      },
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.wallet_link).toBe("https://wallet.example");
  });

  it("should handle different authenticatorAssuranceLevel values", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      authenticatorAssuranceLevel: "substantial",
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.aal).toBe("substantial");
  });

  it("should use the signer's algorithm in the header", async () => {
    const es384Signer: JwtSigner = {
      alg: "ES384",
      method: "jwk",
      publicJwk: mockJwk,
    };

    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      signer: es384Signer,
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.header.alg).toBe("ES384");
  });

  it("should pass correct parameters to signJwt callback", async () => {
    mockSignJwt.mockClear();

    await createClientAttestationJwt(baseOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.objectContaining({
        alg: "ES256",
        trust_chain: ["trust-chain-value-1", "trust-chain-value-2"],
        typ: "oauth-client-attestation+jwt",
      }),
      payload: expect.objectContaining({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: 1700003600,
        iss: "https://issuer.example",
        sub: "client-id-123",
      }),
    });
  });

  it("should throw error if trust_chain is empty", async () => {
    await expect(
      createClientAttestationJwt({
        ...baseOptions,
        // @ts-expect-error - testing invalid input
        trustChain: [],
      }),
    ).rejects.toThrow();
  });

  it("should create jwt even with empty clientId", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      clientId: "",
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.sub).toBe("");
  });

  it("should handle confirmation with additional properties", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      confirmation: {
        jwk: mockJwk,
        key_type: "hardware",
        user_authentication: "biometric",
      },
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.cnf?.jwk).toEqual(mockJwk);
    expect(decoded.payload.cnf?.key_type).toBe("hardware");
    expect(decoded.payload.cnf?.user_authentication).toBe("biometric");
  });

  it("should create jwt with single trust chain value", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      trustChain: ["single-trust-chain"],
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.header.trust_chain).toEqual(["single-trust-chain"]);
  });

  it("should preserve all standard JWT payload fields", async () => {
    const issuedAt = new Date(1700000000000);
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      issuedAt,
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload).toMatchObject({
      aal: "high",
      cnf: { jwk: mockJwk },
      exp: 1700003600,
      iat: 1700000000,
      iss: "https://issuer.example",
      sub: "client-id-123",
    });
  });

  it("should allow additionalPayload to override default claims", async () => {
    const jwt = await createClientAttestationJwt({
      ...baseOptions,
      additionalPayload: {
        aal: "overridden-aal",
      },
    });

    const decoded = decodeJwt({ jwt });
    expect(decoded.payload.aal).toBe("overridden-aal");
  });
});
