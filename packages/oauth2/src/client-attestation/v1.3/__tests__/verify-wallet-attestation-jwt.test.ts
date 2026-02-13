import { encodeToBase64Url } from "@openid4vc/utils";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { verifyWalletAttestationJwt } from "../verify-wallet-attestation-jwt";

describe("verifyWalletAttestationJwt v1.3", () => {
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
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
  }) as { itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 } & IoWalletSdkConfig;

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
  };

  const buildJwt = (header: object, payload: object) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  describe("successful verification", () => {
    it("should verify a valid v1.3 wallet attestation JWT", async () => {
      const jwt = buildJwt(validHeader, validPayload);

      const result = await verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      });

      expect(result.header.x5c).toEqual(mockX5c);
      expect(result.header.typ).toBe("oauth-client-attestation+jwt");
      expect(result.payload.cnf.jwk).toEqual(mockJwk);
      expect(result.payload.sub).toBe("test-client-id");
      expect(result.signer).toBeDefined();
    });

    it("should include optional nbf in payload when present", async () => {
      const nbf = Math.floor(new Date("2025-01-01").getTime() / 1000);
      const jwt = buildJwt(validHeader, { ...validPayload, nbf });

      const result = await verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      });

      expect(result.payload.nbf).toBe(nbf);
    });

    it("should include optional trust_chain in header when present", async () => {
      const headerWithTrustChain = {
        ...validHeader,
        trust_chain: ["jwt1", "jwt2"],
      };
      const jwt = buildJwt(headerWithTrustChain, validPayload);

      const result = await verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      });

      expect(result.header.trust_chain).toEqual(["jwt1", "jwt2"]);
    });
  });

  describe("v1.3 specific constraints", () => {
    it("should fail when x5c is missing from header", async () => {
      const headerWithoutX5c = Object.fromEntries(
        Object.entries(validHeader).filter(([k]) => k !== "x5c"),
      );
      const jwt = buildJwt(headerWithoutX5c, validPayload);

      await expect(
        verifyWalletAttestationJwt({
          callbacks: { verifyJwt: mockVerifyJwt },
          config: mockConfig,
          walletAttestationJwt: jwt,
        }),
      ).rejects.toThrow();
    });

    it("should succeed without aal (not required in v1.3)", async () => {
      const jwt = buildJwt(validHeader, validPayload);

      await expect(
        verifyWalletAttestationJwt({
          callbacks: { verifyJwt: mockVerifyJwt },
          config: mockConfig,
          walletAttestationJwt: jwt,
        }),
      ).resolves.toBeDefined();
    });
  });
});
