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
    status: {
      status_list: {
        idx: 12,
        uri: "https://status.example.com/list",
      },
    },
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
    expect(result.payload.status).toEqual(validPayload.status);
    expect(result.payload.wallet_link).toBe("https://wallet.example.com");
    expect(result.payload.wallet_name).toBe("Test Wallet");
    expect(result.signer).toBeDefined();
  });

  it("should verify a valid v1.4 wallet attestation JWT with eudi_wallet_info", async () => {
    const jwt = buildJwt(validHeader, {
      ...validPayload,
      eudi_wallet_info: {
        general_info: {
          wallet_provider_name: "PagoPA",
          wallet_solution_certification_information:
            "https://certification-reference.example.it",
          wallet_solution_id: "wallet-solution-id",
          wallet_solution_version: "1.0.0",
        },
      },
    });

    const result = await verifyWalletAttestationJwt({
      callbacks: { verifyJwt: mockVerifyJwt },
      config: mockConfig,
      walletAttestationJwt: jwt,
    });

    expect(result.payload.eudi_wallet_info).toEqual({
      general_info: {
        wallet_provider_name: "PagoPA",
        wallet_solution_certification_information:
          "https://certification-reference.example.it",
        wallet_solution_id: "wallet-solution-id",
        wallet_solution_version: "1.0.0",
      },
    });
  });

  it("should reject a JWT missing wallet_link", async () => {
    const payloadWithoutWalletLink: Record<string, unknown> = {
      cnf: validPayload.cnf,
      exp: validPayload.exp,
      iat: validPayload.iat,
      iss: validPayload.iss,
      status: validPayload.status,
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
      status: validPayload.status,
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

  it("should reject a JWT missing status", async () => {
    const payloadWithoutStatus: Record<string, unknown> = {
      cnf: validPayload.cnf,
      exp: validPayload.exp,
      iat: validPayload.iat,
      iss: validPayload.iss,
      sub: validPayload.sub,
      wallet_link: validPayload.wallet_link,
      wallet_name: validPayload.wallet_name,
    };
    const jwt = buildJwt(validHeader, payloadWithoutStatus);

    await expect(
      verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      }),
    ).rejects.toThrow();
  });

  it("should reject malformed eudi_wallet_info", async () => {
    const jwt = buildJwt(validHeader, {
      ...validPayload,
      eudi_wallet_info: {
        general_info: {
          wallet_provider_name: "PagoPA",
        },
      },
    });

    await expect(
      verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      }),
    ).rejects.toThrow();
  });
});
