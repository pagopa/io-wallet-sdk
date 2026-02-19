import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { verifyWalletAttestationJwt } from "../verify-wallet-attestation-jwt";

describe("verifyWalletAttestationJwt v1.0", () => {
  const mockJwk = { crv: "P-256", kty: "EC", x: "x-value", y: "y-value" };
  const mockVerifyJwt = vi.fn(async () => ({
    signerJwk: mockJwk,
    verified: true,
  }));
  const mockConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  }) as { itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 } & IoWalletSdkConfig;

  const validHeader = {
    alg: "ES256",
    kid: "test-kid",
    trust_chain: ["jwt1", "jwt2"],
    typ: "oauth-client-attestation+jwt",
  };
  const validPayload = {
    aal: "https://trust.example/LoA/basic",
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
    it("should verify a valid v1.0 wallet attestation JWT", async () => {
      const jwt = buildJwt(validHeader, validPayload);

      const result = await verifyWalletAttestationJwt({
        callbacks: { verifyJwt: mockVerifyJwt },
        config: mockConfig,
        walletAttestationJwt: jwt,
      });

      expect(result.header.trust_chain).toEqual(["jwt1", "jwt2"]);
      expect(result.header.typ).toBe("oauth-client-attestation+jwt");
      expect(result.payload.aal).toBe("https://trust.example/LoA/basic");
      expect(result.payload.cnf.jwk).toEqual(mockJwk);
      expect(result.payload.sub).toBe("test-client-id");
      expect(result.signer).toBeDefined();
    });
  });

  describe("v1.0 specific constraints", () => {
    it("should fail when trust_chain is missing from header", async () => {
      const headerWithoutTrustChain = Object.fromEntries(
        Object.entries(validHeader).filter(([k]) => k !== "trust_chain"),
      );
      const jwt = buildJwt(headerWithoutTrustChain, validPayload);

      await expect(
        verifyWalletAttestationJwt({
          callbacks: { verifyJwt: mockVerifyJwt },
          config: mockConfig,
          walletAttestationJwt: jwt,
        }),
      ).rejects.toThrow();
    });

    it("should fail when aal is missing from payload", async () => {
      const payloadWithoutAal = Object.fromEntries(
        Object.entries(validPayload).filter(([k]) => k !== "aal"),
      );
      const jwt = buildJwt(validHeader, payloadWithoutAal);

      await expect(
        verifyWalletAttestationJwt({
          callbacks: { verifyJwt: mockVerifyJwt },
          config: mockConfig,
          walletAttestationJwt: jwt,
        }),
      ).rejects.toThrow();
    });

    it("should fail when cnf.jwk is missing from payload", async () => {
      const jwt = buildJwt(validHeader, {
        ...validPayload,
        cnf: {},
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
});
