import { dateToSeconds } from "@openid4vc/utils";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { WalletProviderError } from "../../../errors";
import { createWalletAttestationJwt } from "../create-wallet-attestation-jwt";

describe("createWalletAttestationJwt v1.0", () => {
  const mockSignJwt = vi.fn();
  const mockConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  }) as { itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 } & IoWalletSdkConfig;

  const mockJwk = {
    crv: "P-256",
    kid: "test-key-id",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockSignJwt.mockResolvedValue({
      jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImp3dDEiLCJqd3QyIl19.eyJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QtY2xpZW50LWlkIiwiaWF0IjoxNzM4MjQzMjAwLCJleHAiOjE3NDMzMzk2MDAsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJ0ZXN0LWtleS1pZCIsImt0eSI6IkVDIiwieCI6InRlc3QteC12YWx1ZSIsInkiOiJ0ZXN0LXktdmFsdWUifX19.signature",
    });
  });

  describe("successful JWT creation", () => {
    it("should create a valid wallet attestation JWT with required fields", async () => {
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "federation" as const,
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        },
      };

      const result = await createWalletAttestationJwt(options);

      expect(result).toBe(
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImp3dDEiLCJqd3QyIl19.eyJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QtY2xpZW50LWlkIiwiaWF0IjoxNzM4MjQzMjAwLCJleHAiOjE3NDMzMzk2MDAsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJ0ZXN0LWtleS1pZCIsImt0eSI6IkVDIiwieCI6InRlc3QteC12YWx1ZSIsInkiOiJ0ZXN0LXktdmFsdWUifX19.signature",
      );

      expect(mockSignJwt).toHaveBeenCalledWith(
        options.signer,
        expect.objectContaining({
          header: {
            alg: "ES256",
            kid: "test-kid",
            trust_chain: ["jwt1", "jwt2"],
            typ: "oauth-client-attestation+jwt",
          },
          payload: expect.objectContaining({
            cnf: mockJwk,
            exp: dateToSeconds(new Date("2025-01-25T00:00:00Z")),
            iat: expect.any(Number),
            iss: "https://wallet-provider.example.com",
            sub: "test-key-id",
          }),
        }),
      );
    });

    it("should include both walletLink and walletName when provided", async () => {
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "federation" as const,
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        },
        walletLink: "https://wallet.example.com",
        walletName: "Test Wallet",
      };

      await createWalletAttestationJwt(options);

      expect(mockSignJwt).toHaveBeenCalledWith(
        options.signer,
        expect.objectContaining({
          payload: expect.objectContaining({
            wallet_link: "https://wallet.example.com",
            wallet_name: "Test Wallet",
          }),
        }),
      );
    });
  });

  describe("v1.0 specific constraints", () => {
    it("should set typ header to oauth-client-attestation+jwt", async () => {
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "federation" as const,
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        },
      };

      await createWalletAttestationJwt(options);

      const call = mockSignJwt.mock.calls[0];
      if (!call) throw new Error("call is undefined");
      const header = call[1].header;

      expect(header.typ).toBe("oauth-client-attestation+jwt");
    });
  });

  describe("error handling", () => {
    it("should wrap unexpected errors in WalletProviderError", async () => {
      mockSignJwt.mockRejectedValue(new Error("Unexpected signing error"));

      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "federation" as const,
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        },
      };

      await expect(createWalletAttestationJwt(options)).rejects.toThrow(
        WalletProviderError,
      );
      await expect(createWalletAttestationJwt(options)).rejects.toThrow(
        /Unexpected error during wallet attestation creation/,
      );
    });
  });
});
