import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { verifyWalletAttestationJwt } from "../../wallet-attestation";

describe("verifyWalletAttestationJwt v1.5", () => {
  const mockJwk = { crv: "P-256", kty: "EC", x: "x-value", y: "y-value" };
  const mockX5c = ["MIICert1Base64==", "MIICert2Base64=="] as [
    string,
    ...string[],
  ];
  const mockVerifyJwt = vi.fn(async () => ({
    signerJwk: mockJwk,
    verified: true,
  }));
  const config = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_5,
  }) as IoWalletSdkConfig<ItWalletSpecsVersion.V1_5>;

  const validHeader = {
    alg: "ES256",
    kid: "test-kid",
    typ: "oauth-client-attestation+jwt",
    x5c: mockX5c,
  };

  const validPayload = {
    client_status: {
      exp: Math.floor(new Date("2099-01-01").getTime() / 1000),
      status: { status_list: { idx: 1, uri: "https://wp.example.com/sl" } },
    },
    cnf: { jwk: mockJwk },
    exp: Math.floor(new Date("2099-01-01").getTime() / 1000),
    sub: "https://wp.example.com/wallet-solution",
    wallet_link: "https://wallet.example.com",
    wallet_name: "Test Wallet",
    wallet_version: "1.0.0",
  };

  const buildJwt = (header: object, payload: object) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  const verify = (header: object, payload: object) =>
    verifyWalletAttestationJwt({
      callbacks: { verifyJwt: mockVerifyJwt },
      config,
      walletAttestationJwt: buildJwt(header, payload),
    });

  it("should verify a v1.5 wallet attestation without iss and iat", async () => {
    const result = await verify(validHeader, validPayload);

    expect(result.payload.sub).toBe("https://wp.example.com/wallet-solution");
    expect(result.payload.client_status.status.status_list.idx).toBe(1);
    expect(result.payload.wallet_version).toBe("1.0.0");
  });

  it.each(["client_status", "wallet_version"] as const)(
    "should reject a JWT missing %s",
    async (claim) => {
      const payload = Object.fromEntries(
        Object.entries(validPayload).filter(([key]) => key !== claim),
      );

      await expect(verify(validHeader, payload)).rejects.toThrow();
    },
  );

  it("should reject a JWT missing x5c in the header", async () => {
    const header: Record<string, unknown> = { ...validHeader };
    delete header.x5c;

    await expect(verify(header, validPayload)).rejects.toThrow();
  });

  it("should reject a MAC algorithm before invoking verifyJwt", async () => {
    mockVerifyJwt.mockClear();

    await expect(
      verify({ ...validHeader, alg: "HS256" }, validPayload),
    ).rejects.toThrow();
    expect(mockVerifyJwt).not.toHaveBeenCalled();
  });
});
