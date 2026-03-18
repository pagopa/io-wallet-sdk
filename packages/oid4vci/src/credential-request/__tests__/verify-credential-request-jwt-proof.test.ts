/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { VerifyCredentialRequestJwtProofError } from "../../errors";
import { verifyCredentialRequestJwtProof } from "../verify-credential-request-jwt-proof";

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
const TEST_TRUSTED_WALLET_PROVIDER_ISSUER =
  "https://wallet-provider.example.com";
const DEFAULT_NONCE_EXPIRES_AT = new Date("2030-01-01T00:00:00Z");
const TEST_NOW = new Date("2025-01-01T00:00:00Z");
const TEST_NOW_SECONDS = Math.floor(TEST_NOW.getTime() / 1000);

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
      iat: Math.floor(Date.now() / 1000),
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
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
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
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
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
      const now = new Date("2025-01-01T00:00:00Z");
      const jwt = createJwt({
        payload: {
          iat: Math.floor(now.getTime() / 1000),
        },
      });

      await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
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
        expectedNonce: TEST_NONCE,
        jwt,
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
      });

      expect(mockVerifyJwt).toHaveBeenCalledTimes(1);
      expect(mockCalculateJwkThumbprint).not.toHaveBeenCalled();
    });

    it("should ignore fetchStatusList when provided for v1.0", async () => {
      const jwt = createJwt();
      const fetchStatusList = vi.fn().mockResolvedValue(false);

      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        fetchStatusList,
        jwt,
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
      });

      expect(result.payload.nonce).toBe(TEST_NONCE);
      expect(fetchStatusList).not.toHaveBeenCalled();
    });

    it("should throw when iat is older than 5 minutes", async () => {
      const jwt = createJwt({
        payload: { iat: TEST_NOW_SECONDS - 301 },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          now: TEST_NOW,
        }),
      ).rejects.toThrow(
        /Invalid iat claim in credential request proof JWT: iat claim in JWT is too old/,
      );
    });

    it("should not throw when iat is exactly 5 minutes old", async () => {
      const jwt = createJwt({
        payload: { iat: TEST_NOW_SECONDS - 300 },
      });

      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
        now: TEST_NOW,
      });

      expect(result.payload.iat).toBe(TEST_NOW_SECONDS - 300);
    });

    it("should throw when iat is more than 60 seconds in the future", async () => {
      const jwt = createJwt({
        payload: { iat: TEST_NOW_SECONDS + 61 },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          now: TEST_NOW,
        }),
      ).rejects.toThrow(
        /Invalid iat claim in credential request proof JWT: iat claim in JWT is too far in the future/,
      );
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
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
        trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
      });

      expect(result.header.key_attestation).toBe(keyAttestationJwt);
      expect(result.keyAttestation).toBeDefined();
      expect(result.keyAttestation.payload.attested_keys).toEqual([
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
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
        }),
      ).rejects.toThrow(
        /not signed with a key in the 'key_attestation' jwt payload 'attested_keys'/,
      );
    });

    it("should throw when key_attestation issuer is not trusted", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          trustedWalletProviderIssuers: [
            "https://other-wallet-provider.example.com",
          ],
        }),
      ).rejects.toThrow(
        /Untrusted key attestation issuer: https:\/\/wallet-provider\.example\.com/,
      );
    });

    it("should throw when trustedWalletProviderIssuers is empty", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          trustedWalletProviderIssuers: [],
        }),
      ).rejects.toThrow(
        /trustedWalletProviderIssuers must include at least one trusted wallet provider issuer/,
      );
    });

    it("should throw when key_attestation is missing from header", async () => {
      const jwt = createJwt();

      await expect(async () => {
        await verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
        });
      }).rejects.toThrow(ValidationError);
    });

    it("should call fetchStatusList with key attestation status list reference", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });
      const fetchStatusList = vi.fn().mockResolvedValue(false);

      await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_3,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        fetchStatusList,
        jwt,
        nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
        trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
      });

      expect(fetchStatusList).toHaveBeenCalledWith({
        index: 0,
        uri: "https://status.example.com",
      });
    });

    it("should throw when key attestation is revoked in status list", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          fetchStatusList: vi.fn().mockResolvedValue(true),
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
        }),
      ).rejects.toThrow(/has been revoked/);
    });

    it("should throw when iat is older than 5 minutes", async () => {
      const keyAttestationJwt = createKeyAttestationJwt();
      const jwt = createJwt({
        header: { key_attestation: keyAttestationJwt },
        payload: { iat: TEST_NOW_SECONDS - 301 },
      });

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_3,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
          now: TEST_NOW,
          trustedWalletProviderIssuers: [TEST_TRUSTED_WALLET_PROVIDER_ISSUER],
        }),
      ).rejects.toThrow(
        /Invalid iat claim in credential request proof JWT: iat claim in JWT is too old/,
      );
    });
  });

  describe("common", () => {
    it("should throw when nonce is expired", async () => {
      const now = new Date("2025-01-01T00:00:00Z");
      const jwt = createJwt({
        payload: {
          iat: Math.floor(now.getTime() / 1000),
        },
      });
      const nonceExpiresAt = new Date("2024-12-31T00:00:00Z");

      await expect(
        verifyCredentialRequestJwtProof({
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: configV1_0,
          credentialIssuer: TEST_CREDENTIAL_ISSUER,
          expectedNonce: TEST_NONCE,
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
          expectedNonce: TEST_NONCE,
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
          expectedNonce: TEST_NONCE,
          jwt,
          nonceExpiresAt: DEFAULT_NONCE_EXPIRES_AT,
        }),
      ).rejects.toThrow(VerifyCredentialRequestJwtProofError);
    });

    it("should not throw when nonce has not expired", async () => {
      const now = new Date("2025-01-01T00:00:00Z");
      const jwt = createJwt({
        payload: {
          iat: Math.floor(now.getTime() / 1000),
        },
      });
      const nonceExpiresAt = new Date("2025-01-02T00:00:00Z");

      const result = await verifyCredentialRequestJwtProof({
        callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
        config: configV1_0,
        credentialIssuer: TEST_CREDENTIAL_ISSUER,
        expectedNonce: TEST_NONCE,
        jwt,
        nonceExpiresAt,
        now,
      });

      expect(result.payload.nonce).toBe(TEST_NONCE);
    });
  });
});
