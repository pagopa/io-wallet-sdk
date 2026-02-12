import { dateToSeconds } from "@openid4vc/utils";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ClientAttestationError } from "../../../errors";
import { createWalletAttestationJwt } from "../create-wallet-attestation-jwt";

describe("createWalletAttestationJwt v1.3", () => {
  const mockSignJwt = vi.fn();
  const mockConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
  }) as { itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 } & IoWalletSdkConfig;

  const mockJwk = {
    crv: "P-256",
    kid: "test-key-id",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  };

  const mockX5c = ["MIICertificate1Base64==", "MIICertificate2Base64=="] as [
    string,
    ...string[],
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    mockSignJwt.mockResolvedValue({
      jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsIng1YyI6WyJNSUlDZXJ0aWZpY2F0ZTFCYXNlNjQ9PSIsIk1JSUNLZXJ0aWZpY2F0ZTJCYXNlNjQ9PSJdfQ.eyJpc3MiOiJodHRwczovL3dhbGxldC1wcm92aWRlci5leGFtcGxlLmNvbSIsInN1YiI6InRlc3QtY2xpZW50LWlkIiwiaWF0IjoxNzM4MjQzMjAwLCJleHAiOjE3NDMzMzk2MDAsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJ0ZXN0LWtleS1pZCIsImt0eSI6IkVDIiwieCI6InRlc3QteC12YWx1ZSIsInkiOiJ0ZXN0LXktdmFsdWUifX19.signature",
    });
  });

  describe("successful JWT creation", () => {
    it("should create a valid wallet attestation JWT with x5c", async () => {
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "x5c" as const,
          x5c: mockX5c,
        },
      };

      const result = await createWalletAttestationJwt(options);

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");

      expect(mockSignJwt).toHaveBeenCalledWith(
        options.signer,
        expect.objectContaining({
          header: {
            alg: "ES256",
            kid: "test-kid",
            typ: "oauth-client-attestation+jwt",
            x5c: mockX5c,
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

    it("should include optional nbf when provided", async () => {
      const nbfDate = new Date("2025-01-01T00:00:00Z");
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        nbf: nbfDate,
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "x5c" as const,
          x5c: mockX5c,
        },
      };

      await createWalletAttestationJwt(options);

      expect(mockSignJwt).toHaveBeenCalledWith(
        options.signer,
        expect.objectContaining({
          payload: expect.objectContaining({
            nbf: dateToSeconds(nbfDate),
          }),
        }),
      );
    });
  });

  describe("nbf validation", () => {
    it("should accept when nbf is before exp", async () => {
      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        nbf: new Date("2025-01-01T00:00:00Z"),
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "x5c" as const,
          x5c: mockX5c,
        },
      };

      await expect(createWalletAttestationJwt(options)).resolves.toBeDefined();
    });
  });

  describe("error handling", () => {
    it("should wrap unexpected errors in ClientAttestationError", async () => {
      mockSignJwt.mockRejectedValue(new Error("Crypto module crashed"));

      const options = {
        callbacks: { signJwt: mockSignJwt },
        config: mockConfig,
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-01-25T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "test-kid",
          method: "x5c" as const,
          x5c: mockX5c,
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
