import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { verifyWalletAttestationJwt } from "../verify-wallet-attestation-jwt";

describe("verifyWalletAttestationJwt v1.4", () => {
  const mockJwk = { crv: "P-256", kty: "EC", x: "x-value", y: "y-value" };
  const mockX5c = ["MIICert1Base64==", "MIICert2Base64=="] as [
    string,
    ...string[],
  ];
  const mockVerifyJwt = vi.fn(async () => ({
    signerJwk: mockJwk,
    verified: true,
  }));
  const mockConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
  }) as { itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 } & IoWalletSdkConfig;

  const validHeader = {
    alg: "ES256",
    kid: "test-kid",
    typ: "oauth-client-attestation+jwt",
    x5c: mockX5c,
  };

  const validPayload = {
    cnf: { jwk: mockJwk },
    exp: Math.floor(new Date("2099-01-01").getTime() / 1000),
    iat: Math.floor(Date.now() / 1000),
    iss: "https://wallet-provider.example.com",
    sub: "test-client-id",
    wallet_link: "https://wallet.example.com",
    wallet_name: "Test Wallet",
  };

  const buildJwt = (header: object, payload: object) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  it("should verify a valid v1.4 wallet attestation JWT", async () => {
    const jwt = buildJwt(validHeader, validPayload);

    const result = await verifyWalletAttestationJwt({
      callbacks: { verifyJwt: mockVerifyJwt },
      config: mockConfig,
      walletAttestationJwt: jwt,
    });

    expect(result.header.x5c).toEqual(mockX5c);
    expect(result.payload.wallet_link).toBe("https://wallet.example.com");
    expect(result.payload.wallet_name).toBe("Test Wallet");
    expect(result.signer).toBeDefined();
  });

  it("should reject a JWT missing wallet_link", async () => {
    const payloadWithoutWalletLink: Record<string, unknown> = {
      cnf: validPayload.cnf,
      exp: validPayload.exp,
      iat: validPayload.iat,
      iss: validPayload.iss,
      sub: validPayload.sub,
      wallet_name: validPayload.wallet_name,
    };
    const jwt = buildJwt(validHeader, payloadWithoutWalletLink);

    await expect(
      verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      }),
    ).rejects.toThrow();
  });

  it("should reject a JWT missing wallet_name", async () => {
    const payloadWithoutWalletName: Record<string, unknown> = {
      cnf: validPayload.cnf,
      exp: validPayload.exp,
      iat: validPayload.iat,
      iss: validPayload.iss,
      sub: validPayload.sub,
      wallet_link: validPayload.wallet_link,
    };
    const jwt = buildJwt(validHeader, payloadWithoutWalletName);

    await expect(
      verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      }),
    ).rejects.toThrow();
  });

  it("should accept a JWT carrying claims unknown to v1.4.6", async () => {
    const jwt = buildJwt(validHeader, {
      ...validPayload,
      status: { status_list: { idx: 12, uri: "https://status.example.com" } },
    });

    const result = await verifyWalletAttestationJwt({
      callbacks: { verifyJwt: mockVerifyJwt },
      config: mockConfig,
      walletAttestationJwt: jwt,
    });

    expect(result.payload.wallet_name).toBe("Test Wallet");
  });

  it("should reject a JWT missing kid in the header", async () => {
    const jwt = buildJwt(
      {
        alg: validHeader.alg,
        typ: validHeader.typ,
        x5c: validHeader.x5c,
      },
      validPayload,
    );

    await expect(
      verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      }),
    ).rejects.toThrow();
  });
});
