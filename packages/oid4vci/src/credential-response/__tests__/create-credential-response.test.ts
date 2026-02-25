/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import type {
  CreateCredentialResponseOptionsV1_0,
  CreateCredentialResponseOptionsV1_3,
} from "../types";

import { Oid4vciError } from "../../errors";
import { createCredentialResponse } from "../create-credential-response";
import {
  zCredentialResponseV1_0,
  zCredentialResponseV1_3,
} from "../z-credential-response";

describe("createCredentialResponse", () => {
  describe("v1.0", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    describe("immediate flow", () => {
      it("should create a credential response with credentials", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
          },
        });

        expect(result.credentialResponse).toEqual({
          credentials: [{ credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" }],
        });
        expect(result.credentialResponseJwt).toBeUndefined();
      });

      it("should create a credential response with multiple credentials", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "credential-1" },
              { credential: "credential-2" },
            ],
          },
        });

        expect(result.credentialResponse.credentials).toHaveLength(2);
      });

      it("should include notification_id when provided", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
            notificationId: "notif-123",
          },
        });

        expect(result.credentialResponse).toEqual({
          credentials: [{ credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" }],
          notification_id: "notif-123",
        });
      });

      it("should omit notification_id when not provided", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
          },
        });

        expect(result.credentialResponse).not.toHaveProperty("notification_id");
      });
    });

    describe("deferred flow", () => {
      it("should create a deferred response with lead_time and transaction_id", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            leadTime: 86400,
            transactionId: "tx-abc-123",
          },
        });

        expect(result.credentialResponse).toEqual({
          lead_time: 86400,
          transaction_id: "tx-abc-123",
        });
      });

      it("should not include credentials in deferred response", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            leadTime: 300,
            transactionId: "tx-deferred",
          },
        });

        expect(result.credentialResponse).not.toHaveProperty("credentials");
        expect(result.credentialResponse).not.toHaveProperty("notification_id");
        expect(result.credentialResponse).not.toHaveProperty("interval");
      });
    });

    describe("validation", () => {
      it("should throw ValidationError for invalid lead_time (negative)", async () => {
        await expect(
          createCredentialResponse({
            config,
            flow: {
              leadTime: -1,
              transactionId: "tx-abc",
            },
          }),
        ).rejects.toThrow(ValidationError);
      });

      it("should reject interval in deferred flow at type level", () => {
        const invalidOptions: CreateCredentialResponseOptionsV1_0 = {
          config,
          flow: {
            // @ts-expect-error - interval is not valid for v1.0 deferred flow
            interval: 300,
            transactionId: "tx-abc",
          },
        };

        expect(invalidOptions).toBeDefined();
      });
    });
  });

  describe("v1.3", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    describe("immediate flow", () => {
      it("should create a credential response with credentials", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
          },
        });

        expect(result.credentialResponse).toEqual({
          credentials: [{ credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" }],
        });
        expect(result.credentialResponseJwt).toBeUndefined();
      });

      it("should create a credential response with multiple credentials", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "credential-1" },
              { credential: "credential-2" },
            ],
          },
        });

        expect(result.credentialResponse.credentials).toHaveLength(2);
      });

      it("should include notification_id when provided", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
            notificationId: "notif-456",
          },
        });

        expect(result.credentialResponse).toEqual({
          credentials: [{ credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" }],
          notification_id: "notif-456",
        });
      });

      it("should omit notification_id when not provided", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            credentials: [
              { credential: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" },
            ],
          },
        });

        expect(result.credentialResponse).not.toHaveProperty("notification_id");
      });
    });

    describe("deferred flow", () => {
      it("should create a deferred response with interval and transaction_id", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            interval: 300,
            transactionId: "tx-abc-123",
          },
        });

        expect(result.credentialResponse).toEqual({
          interval: 300,
          transaction_id: "tx-abc-123",
        });
      });

      it("should not include credentials in deferred response", async () => {
        const result = await createCredentialResponse({
          config,
          flow: {
            interval: 60,
            transactionId: "tx-deferred",
          },
        });

        expect(result.credentialResponse).not.toHaveProperty("credentials");
        expect(result.credentialResponse).not.toHaveProperty("notification_id");
        expect(result.credentialResponse).not.toHaveProperty("lead_time");
      });
    });

    describe("validation", () => {
      it("should throw ValidationError for invalid interval (negative)", async () => {
        await expect(
          createCredentialResponse({
            config,
            flow: {
              interval: -1,
              transactionId: "tx-abc",
            },
          }),
        ).rejects.toThrow(ValidationError);
      });

      it("should reject leadTime in deferred flow at type level", () => {
        const invalidOptions: CreateCredentialResponseOptionsV1_3 = {
          config,
          flow: {
            // @ts-expect-error - leadTime is not valid for v1.3 deferred flow
            leadTime: 300,
            transactionId: "tx-abc",
          },
        };

        expect(invalidOptions).toBeDefined();
      });
    });
  });

  describe("schema exclusivity", () => {
    it("should reject mixed immediate and deferred fields for v1.0", () => {
      const mixedResponse = {
        credentials: [{ credential: "test-credential" }],
        lead_time: 300,
        transaction_id: "tx-abc",
      };

      const result = zCredentialResponseV1_0.safeParse(mixedResponse);

      expect(result.success).toBe(false);
    });

    it("should reject mixed immediate and deferred fields for v1.3", () => {
      const mixedResponse = {
        credentials: [{ credential: "test-credential" }],
        interval: 300,
        transaction_id: "tx-abc",
      };

      const result = zCredentialResponseV1_3.safeParse(mixedResponse);

      expect(result.success).toBe(false);
    });

    it("should reject notification_id without credentials", () => {
      const invalidResponse = {
        notification_id: "notif-123",
        transaction_id: "tx-abc",
      };

      expect(zCredentialResponseV1_0.safeParse(invalidResponse).success).toBe(
        false,
      );
      expect(zCredentialResponseV1_3.safeParse(invalidResponse).success).toBe(
        false,
      );
    });
  });

  describe("encryption", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    const credentialResponseEncryption = {
      alg: "ECDH-ES",
      enc: "A256GCM",
      jwk: {
        crv: "P-256",
        kty: "EC",
        x: "test-x",
        y: "test-y",
      },
    };

    it("should encrypt the response when credentialResponseEncryption and encryptJwe are provided", async () => {
      const mockEncryptJwe = vi.fn().mockResolvedValue({
        encryptionJwk: credentialResponseEncryption.jwk,
        jwe: "encrypted-jwe-token",
      });

      const result = await createCredentialResponse({
        callbacks: { encryptJwe: mockEncryptJwe },
        config,
        credentialResponseEncryption,
        flow: {
          credentials: [{ credential: "test-credential" }],
        },
      });

      expect(result.credentialResponseJwt).toBe("encrypted-jwe-token");
      expect(result.credentialResponse).toEqual({
        credentials: [{ credential: "test-credential" }],
      });
      expect(mockEncryptJwe).toHaveBeenCalledWith(
        {
          alg: "ECDH-ES",
          enc: "A256GCM",
          method: "jwk",
          publicJwk: credentialResponseEncryption.jwk,
        },
        JSON.stringify({ credentials: [{ credential: "test-credential" }] }),
      );
    });

    it("should throw Oid4vciError when credentialResponseEncryption is provided without encryptJwe callback", async () => {
      await expect(
        createCredentialResponse({
          config,
          credentialResponseEncryption,
          flow: {
            credentials: [{ credential: "test-credential" }],
          },
        }),
      ).rejects.toThrow(Oid4vciError);
    });

    it("should not encrypt when credentialResponseEncryption is not provided", async () => {
      const result = await createCredentialResponse({
        config,
        flow: {
          credentials: [{ credential: "test-credential" }],
        },
      });

      expect(result.credentialResponseJwt).toBeUndefined();
    });
  });

  describe("error handling", () => {
    it("should throw ItWalletSpecsVersionError for unsupported version", async () => {
      const invalidConfig = {
        isVersion: () => false,
        itWalletSpecsVersion: "99.99.99",
      };

      await expect(
        createCredentialResponse({
          // @ts-expect-error - Testing invalid version (not in union type)
          config: invalidConfig,
          flow: {
            credentials: [{ credential: "test" }],
          },
        }),
      ).rejects.toThrow(ItWalletSpecsVersionError);
    });
  });
});
