import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  dateToSeconds,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ClientAttestationError } from "../../../errors";
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

  // Mock JWT with aal at top-level payload:
  // header: {"alg":"ES256","typ":"oauth-client-attestation+jwt","kid":"test-kid","trust_chain":["jwt1","jwt2"]}
  // payload: {"iss":"https://wallet-provider.example.com","sub":"test-client-id","iat":1738243200,"exp":1743339600,"cnf":{"jwk":{"crv":"P-256","kid":"test-key-id","kty":"EC","x":"test-x-value","y":"test-y-value"}},"aal":"aal1"}
  const mockJwt =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImp3dDEiLCJqd3QyIl19.eyJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QtY2xpZW50LWlkIiwiaWF0IjoxNzM4MjQzMjAwLCJleHAiOjE3NDMzMzk2MDAsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJ0ZXN0LWtleS1pZCIsImt0eSI6IkVDIiwieCI6InRlc3QteC12YWx1ZSIsInkiOiJ0ZXN0LXktdmFsdWUifX0sImFhbCI6ImFhbDEifQ.signature";

  beforeEach(() => {
    vi.clearAllMocks();
    mockSignJwt.mockResolvedValue({ jwt: mockJwt });
  });

  describe("successful JWT creation", () => {
    it("should create a valid wallet attestation JWT with required fields", async () => {
      const options = {
        authenticatorAssuranceLevel: "aal1",
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

      expect(result).toBe(mockJwt);

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
            aal: "aal1",
            cnf: { jwk: mockJwk },
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
        authenticatorAssuranceLevel: "aal1",
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
        authenticatorAssuranceLevel: "aal1",
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
    it("should wrap unexpected errors in ClientAttestationError", async () => {
      mockSignJwt.mockRejectedValue(new Error("Unexpected signing error"));

      const options = {
        authenticatorAssuranceLevel: "aal1",
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
        ClientAttestationError,
      );
      await expect(createWalletAttestationJwt(options)).rejects.toThrow(
        /Unexpected error during wallet attestation creation/,
      );
    });
  });
});
