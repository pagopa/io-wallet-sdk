import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  decodeBase64,
  encodeToBase64Url,
  encodeToUtf8String,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { Oauth2Error } from "../../errors";
import {
  createClientAttestationPopJwt,
  verifyClientAttestationPopJwt,
} from "../client-attestation-pop";

describe("client-attestation-pop", () => {
  const mockConfigV1_0 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  });
  const mockConfigV1_3 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
  });
  const mockConfigV1_4 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
  });
  const mockJwk = { crv: "P-256", kty: "EC", x: "...", y: "..." };
  const mockHeader = { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" };
  const mockPayload = {
    cnf: { jwk: mockJwk },
    sub: "client-id",
  };
  const mockClientAttestation = [
    encodeToBase64Url(JSON.stringify(mockHeader)),
    encodeToBase64Url(JSON.stringify(mockPayload)),
    "signature",
  ].join(".");

  const mockSignJwt = vi.fn(async (_signer, { header, payload }) => ({
    jwt: [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join("."),
    signerJwk: mockJwk,
  }));
  const mockGenerateRandom = vi.fn(async (len) => new Uint8Array(len));
  const mockVerifyJwt = vi.fn(async () => ({
    signerJwk: mockJwk,
    verified: true,
  }));
  const decodeJwtPayload = (jwt: string) => {
    const payloadPart = jwt.split(".")[1];
    if (!payloadPart) throw new Error("JWT payload part is missing");
    return JSON.parse(encodeToUtf8String(decodeBase64(payloadPart))) as Record<
      string,
      unknown
    >;
  };

  it("should create a client attestation pop jwt", async () => {
    const jwt = await createClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
      clientAttestation: mockClientAttestation,
      config: mockConfigV1_0,
      issuedAt: new Date(1700000000000),
    });
    expect(typeof jwt).toBe("string");
    expect(jwt.split(".").length).toBe(3);
  });

  it("should include exp in the client attestation pop jwt payload for IT-Wallet v1.0", async () => {
    const jwt = await createClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
      clientAttestation: mockClientAttestation,
      config: mockConfigV1_0,
      expiresAt: new Date("2025-01-01T00:01:00.000Z"),
      issuedAt: new Date("2025-01-01T00:00:00.000Z"),
    });

    expect(decodeJwtPayload(jwt)).toMatchObject({
      exp: 1735689660,
    });
  });

  it("should not include exp in the client attestation pop jwt payload for IT-Wallet v1.3", async () => {
    const jwt = await createClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
      clientAttestation: mockClientAttestation,
      config: mockConfigV1_3,
      issuedAt: new Date("2025-01-01T00:00:00.000Z"),
    });

    expect(decodeJwtPayload(jwt)).not.toHaveProperty("exp");
  });

  it("should not include exp in the client attestation pop jwt payload for IT-Wallet v1.4", async () => {
    const jwt = await createClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
      clientAttestation: mockClientAttestation,
      config: mockConfigV1_4,
      issuedAt: new Date("2025-01-01T00:00:00.000Z"),
    });

    expect(decodeJwtPayload(jwt)).not.toHaveProperty("exp");
  });

  it("should throw if client attestation does not contain cnf.jwk", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ sub: "client-id" })),
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
        config: mockConfigV1_0,
      }),
    ).rejects.toThrow(/cnf\.jwk/);
  });

  it("should throw if client attestation does not contain sub", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ cnf: { jwk: mockJwk } })),
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
        config: mockConfigV1_0,
      }),
    ).rejects.toThrow(/sub/);
  });

  it("should throw if clientAttestation is malformed", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      "asdf",
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
        config: mockConfigV1_0,
      }),
    ).rejects.toThrow(Oauth2Error);
  });

  it("should verify a valid client attestation pop jwt", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(
        JSON.stringify({ aud: "https://auth.example", sub: "client-id" }),
      ),
      "signature",
    ].join(".");
    const result = await verifyClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { verifyJwt: mockVerifyJwt },
      clientAttestationPopJwt: jwt,
      clientAttestationPublicJwk: mockJwk,
    });
    expect(result.header.alg).toBe("ES256");
    expect(result.payload.aud).toBe("https://auth.example");
    expect(result.signer).toBeDefined();
  });

  it("should throw if aud does not match", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ aud: "wrong", sub: "client-id" })),
      "signature",
    ].join(".");
    await expect(
      verifyClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { verifyJwt: mockVerifyJwt },
        clientAttestationPopJwt: jwt,
        clientAttestationPublicJwk: mockJwk,
      }),
    ).rejects.toThrow(/aud/);
  });

  it("should throw if jwt is malformed", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      "asdf",
      "signature",
    ].join(".");
    await expect(
      verifyClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { verifyJwt: mockVerifyJwt },
        clientAttestationPopJwt: jwt,
        clientAttestationPublicJwk: mockJwk,
      }),
    ).rejects.toThrow(Oauth2Error);
  });
});

describe("CreateClientAttestationPopJwtOptions", () => {
  it("should only allow expiresAt for IT-Wallet v1.0", () => {
    const mockCallbacks = {
      generateRandom: vi.fn(async (len) => new Uint8Array(len)),
      signJwt: vi.fn(),
    };
    const createV1_0 = () =>
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: mockCallbacks,
        clientAttestation: "header.payload.signature",
        config: new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
        }),
        expiresAt: new Date("2025-01-01T00:01:00.000Z"),
      });

    const createV1_3 = () =>
      // @ts-expect-error expiresAt is only available for IT-Wallet v1.0 options
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: mockCallbacks,
        clientAttestation: "header.payload.signature",
        config: new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
        }),
        expiresAt: new Date("2025-01-01T00:01:00.000Z"),
      });

    expect(createV1_0).toBeDefined();
    expect(createV1_3).toBeDefined();
  });

  it("should allow base options for other IT-Wallet versions", () => {
    const mockCallbacks = {
      generateRandom: vi.fn(async (len) => new Uint8Array(len)),
      signJwt: vi.fn(),
    };
    const createV1_3 = () =>
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: mockCallbacks,
        clientAttestation: "header.payload.signature",
        config: new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
        }),
      });

    expect(createV1_3).toBeDefined();
  });
});
