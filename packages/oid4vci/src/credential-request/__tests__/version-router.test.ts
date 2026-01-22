import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  CredentialRequestOptionsV1_0,
  CredentialRequestOptionsV1_3,
} from "../types";

import { createCredentialRequest } from "../create-credential-request";

const mockCallbacks = {
  signJwt: vi.fn(),
};

const mockSigner = {
  alg: "ES256" as const,
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid-router",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

// eslint-disable-next-line max-lines-per-function
describe("createCredentialRequest Version Router", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockCallbacks.signJwt.mockResolvedValue({
      jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test-signature",
    });
  });

  describe("v1.0 routing", () => {
    it("should route to v1.0 implementation when configured", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });

      const result = await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_0);

      // v1.0 returns singular `proof` object
      expect(result).toHaveProperty("proof");
      expect(result).not.toHaveProperty("proofs");
      expect(result.proof).toHaveProperty("proof_type", "jwt");
    });

    it("should NOT include key_attestation in JWT header for v1.0", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });

      await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_0);

      const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
      expect(signJwtCall).toBeDefined();
      if (!signJwtCall) throw new Error("signJwtCall is undefined");

      expect(signJwtCall[1].header).not.toHaveProperty("key_attestation");
    });

    it("should throw error when keyAttestation provided with v1.0", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });

      // TypeScript prevents this, but test runtime behavior
      type InvalidOptions = {
        keyAttestation: string;
      } & CredentialRequestOptionsV1_0;

      await expect(
        createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          config,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          keyAttestation: "eyJ...should-not-be-here", // Invalid for v1.0
          nonce: "test-nonce",
          signer: mockSigner,
        } as InvalidOptions),
      ).rejects.toThrow(ItWalletSpecsVersionError);

      await expect(
        createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          config,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          keyAttestation: "eyJ...should-not-be-here",
          nonce: "test-nonce",
          signer: mockSigner,
        } as InvalidOptions),
      ).rejects.toThrow("keyAttestation parameter");
    });
  });

  describe("v1.3 routing", () => {
    it("should route to v1.3 implementation when configured", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      });

      const result = await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        keyAttestation: "eyJhbGciOiJFUzI1NiJ9.key-attestation.sig",
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_3);

      // v1.3 returns plural `proofs` object with JWT array
      expect(result).toHaveProperty("proofs");
      expect(result).not.toHaveProperty("proof");
      expect(result.proofs.jwt).toBeInstanceOf(Array);
    });

    it("should include key_attestation in JWT header for v1.3", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      });
      const keyAttestation = "eyJhbGciOiJFUzI1NiJ9.key-attestation.sig";

      await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        keyAttestation,
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_3);

      const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
      expect(signJwtCall).toBeDefined();
      if (!signJwtCall) throw new Error("signJwtCall is undefined");

      expect(signJwtCall[1].header).toHaveProperty(
        "key_attestation",
        keyAttestation,
      );
    });
  });

  describe("Version-specific return types", () => {
    it("v1.0 returns CredentialRequestV1_0 type", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });

      const result = await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_0);

      // Type narrowing - TypeScript should infer this as CredentialRequestV1_0
      expect("proof" in result).toBe(true);
      if ("proof" in result) {
        expect(result.proof.proof_type).toBe("jwt");
        expect(typeof result.proof.jwt).toBe("string");
      }
    });

    it("v1.3 returns CredentialRequestV1_3 type", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      });

      const result = await createCredentialRequest({
        callbacks: mockCallbacks,
        clientId: "test-client-id",
        config,
        credential_identifier: "test-credential",
        issuerIdentifier: "https://issuer.example.com",
        keyAttestation: "eyJhbGciOiJFUzI1NiJ9.key-attestation.sig",
        nonce: "test-nonce",
        signer: mockSigner,
      } as CredentialRequestOptionsV1_3);

      // Type narrowing - TypeScript should infer this as CredentialRequestV1_3
      expect("proofs" in result).toBe(true);
      if ("proofs" in result) {
        expect(Array.isArray(result.proofs.jwt)).toBe(true);
        expect(result.proofs.jwt).toHaveLength(1);
      }
    });
  });

  describe("Error handling", () => {
    it("should throw ItWalletSpecsVersionError for unsupported version", async () => {
      // Simulate invalid version by forcing a config with wrong version
      const invalidConfig = {
        itWalletSpecsVersion: "99.99.99",
      };

      await expect(
        createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          // @ts-expect-error - Testing invalid version (not in union type)
          config: invalidConfig,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          nonce: "test-nonce",
          signer: mockSigner,
        }),
      ).rejects.toThrow(ItWalletSpecsVersionError);
    });

    it("should include supported versions in error message", async () => {
      const invalidConfig = {
        itWalletSpecsVersion: "2.0.0",
      };

      try {
        await createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          // @ts-expect-error - Testing invalid version (not in union type)
          config: invalidConfig,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          nonce: "test-nonce",
          signer: mockSigner,
        });
        throw new Error("Expected error to be thrown");
      } catch (error) {
        if (error instanceof ItWalletSpecsVersionError) {
          expect(error.supportedVersions).toContain(ItWalletSpecsVersion.V1_0);
          expect(error.supportedVersions).toContain(ItWalletSpecsVersion.V1_3);
        } else {
          throw error;
        }
      }
    });
  });

  describe("Parameter validation across versions", () => {
    it("v1.0 works with all required params (no keyAttestation)", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });

      await expect(
        createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          config,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          nonce: "test-nonce",
          signer: mockSigner,
        } as CredentialRequestOptionsV1_0),
      ).resolves.toBeDefined();
    });

    it("v1.3 requires keyAttestation parameter", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      });

      await expect(
        createCredentialRequest({
          callbacks: mockCallbacks,
          clientId: "test-client-id",
          config,
          credential_identifier: "test-credential",
          issuerIdentifier: "https://issuer.example.com",
          keyAttestation: "eyJhbGciOiJFUzI1NiJ9.key-attestation.sig", // Required
          nonce: "test-nonce",
          signer: mockSigner,
        } as CredentialRequestOptionsV1_3),
      ).resolves.toBeDefined();
    });
  });
});
