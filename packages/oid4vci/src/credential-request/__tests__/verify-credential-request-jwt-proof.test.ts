/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { VerifyCredentialRequestJwtProofError } from "../../errors";
import {
  type VerifyCredentialRequestJwtProofResultV1_3,
  verifyCredentialRequestJwtProof,
} from "../verify-credential-request-jwt-proof";

const { mockCalculateJwkThumbprint, mockVerifyJwt } = vi.hoisted(() => ({
  mockCalculateJwkThumbprint: vi.fn(),
  mockVerifyJwt: vi.fn(),
}));

vi.mock("@openid4vc/oauth2", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/oauth2")>();
  return {
    ...actual,
    calculateJwkThumbprint: mockCalculateJwkThumbprint,
    verifyJwt: mockVerifyJwt,
  };
});

const TEST_CREDENTIAL_ISSUER = "https://issuer.example.com";
const TEST_CLIENT_ID = "test-client-id";
const TEST_NONCE = "test-c-nonce";

const configV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
});

const configV1_3 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const mockPublicJwk = {
  crv: "P-256",
  kty: "EC",
  x: "test-x",
  y: "test-y",
};

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: mockPublicJwk,
};

function createJwt(options?: {
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}): string {
  const header = Base64.encode(
    JSON.stringify({
      alg: "ES256",
      jwk: mockPublicJwk,
      typ: "openid4vci-proof+jwt",
      ...options?.header,
    }),
    true,
  );

  const payload = Base64.encode(
    JSON.stringify({
      aud: TEST_CREDENTIAL_ISSUER,
      iat: 1700000000,
      iss: TEST_CLIENT_ID,
      nonce: TEST_NONCE,
      ...options?.payload,
    }),
    true,
  );

  return `${header}.${payload}.signature`;
}

function createKeyAttestationJwt(): string {
  const header = Base64.encode(
    JSON.stringify({
      alg: "ES256",
      kid: "ka-key-1",
      typ: "key-attestation+jwt",
      x5c: ["cert-chain-1"],
    }),
    true,
  );

  const payload = Base64.encode(
    JSON.stringify({
      attested_keys: [mockPublicJwk],
      exp: 1700100000,
      iat: 1700000000,
      iss: "https://wallet-provider.example.com",
      key_storage: ["iso_18045_high"],
      status: { status_list: { idx: 0, uri: "https://status.example.com" } },
      user_authentication: ["iso_18045_high"],
    }),
    true,
  );

  return `${header}.${payload}.signature`;
}

describe("verifyCredentialRequestJwtProof", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockVerifyJwt.mockResolvedValue({
      signer: mockSigner,
      verified: true,
    });
    mockCalculateJwkThumbprint.mockResolvedValue("thumbprint-1");
  });

  describe("v1.0", () => {
    it("should verify a jwt proof without key_attestation", async () => {
      const jwt = createJwt();
      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        clientId: TEST_CLIENT_ID,
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
      });

      expect(result.header.typ).toBe("openid4vci-proof+jwt");
      expect(result.payload.aud).toBe(TEST_CREDENTIAL_ISSUER);
      expect(result.payload.nonce).toBe(TEST_NONCE);
      expect(result.signer).toEqual(mockSigner);
      expect("keyAttestation" in result).toBe(false);
    });

    it("should pass expectedNonce, expectedAudience and expectedIssuer to verifyJwt", async () => {
      const jwt = createJwt();

      await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        clientId: TEST_CLIENT_ID,
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
      });

      expect(mockVerifyJwt).toHaveBeenCalledWith(
        expect.objectContaining({
          expectedAudience: TEST_CREDENTIAL_ISSUER,
          expectedIssuer: TEST_CLIENT_ID,
          expectedNonce: TEST_NONCE,
        }),
      );
    });

    it("should pass now option to verifyJwt", async () => {
      const jwt = createJwt();
      const now = new Date("2025-01-01T00:00:00Z");

      await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        jwt,
        now,
      });

      expect(mockVerifyJwt).toHaveBeenCalledWith(
        expect.objectContaining({ now }),
      );
    });

    it("should not invoke key attestation verification", async () => {
      const jwt = createJwt();

      await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        jwt,
      });

      expect(mockVerifyJwt).toHaveBeenCalledTimes(1);
      expect(mockCalculateJwkThumbprint).not.toHaveBeenCalled();
    });
  });

  describe("v1.3", () => {
    it("should verify a jwt proof with key_attestation", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });

      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        clientId: TEST_CLIENT_ID,
        config: configV1_3,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
      });

      expect(result.header.key_attestation).toBe(keyAttestationJwt);
      const v1_3Result = result as VerifyCredentialRequestJwtProofResultV1_3;
      expect(v1_3Result.keyAttestation).toBeDefined();
      expect(v1_3Result.keyAttestation.payload.attested_keys).toEqual([
        mockPublicJwk,
      ]);
      expect(mockVerifyJwt).toHaveBeenCalledTimes(2);
    });

    it("should throw when signer key is not in key_attestation attested_keys", async () => {
      mockCalculateJwkThumbprint
        .mockResolvedValueOnce("signer-thumbprint")
        .mockResolvedValueOnce("different-thumbprint");

      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          jwt,
        }),
      ).rejects.toThrow(
        /not signed with a key in the 'key_attestation' jwt payload 'attested_keys'/,
      );
    });

    it("should throw when key_attestation is missing from header", async () => {
      const jwt = createJwt();

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          jwt,
        }),
      ).rejects.toThrow();
    });
  });

  describe("common", () => {
    it("should throw when nonce is expired", async () => {
      const jwt = createJwt();
      const now = new Date("2025-01-01T00:00:00Z");
      const nonceExpiresAt = new Date("2024-12-31T00:00:00Z");

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          jwt,
          nonceExpiresAt,
          now,
        }),
      ).rejects.toThrow(VerifyCredentialRequestJwtProofError);

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          jwt,
          nonceExpiresAt,
          now,
        }),
      ).rejects.toThrow(/Nonce used for credential request proof expired/);
    });

    it("should throw when jwt signature verification fails", async () => {
      mockVerifyJwt.mockRejectedValue(new Error("Signature invalid"));
      const jwt = createJwt();

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          jwt,
        }),
      ).rejects.toThrow(VerifyCredentialRequestJwtProofError);
    });

    it("should not throw when nonce has not expired", async () => {
      const jwt = createJwt();
      const now = new Date("2025-01-01T00:00:00Z");
      const nonceExpiresAt = new Date("2025-01-02T00:00:00Z");

      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        jwt,
        nonceExpiresAt,
        now,
      });

      expect(result.payload.nonce).toBe(TEST_NONCE);
    });
  });
});
