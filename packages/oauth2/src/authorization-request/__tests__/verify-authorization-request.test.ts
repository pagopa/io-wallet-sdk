/* eslint-disable max-lines-per-function */
import {
  AuthorizationServerMetadata,
  CallbackContext,
  Jwk,
} from "@openid4vc/oauth2";
import { encodeToBase64Url } from "@openid4vc/utils";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  RequestLike,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { Oauth2Error } from "../../errors";
import {
  VerifyAuthorizationRequestOptions,
  verifyAuthorizationRequest,
} from "../verify-authorization-request";

describe("verifyAuthorizationRequest", () => {
  const mockJwk: Jwk = {
    crv: "P-256",
    kty: "EC",
    x: "test-x",
    y: "test-y",
  };

  const mockRequest: RequestLike = {
    headers: new Headers(),
    method: "POST",
    url: "https://auth.example.com/par",
  };

  const mockCallbacks: Pick<CallbackContext, "hash" | "verifyJwt"> = {
    hash: vi.fn(async (data, alg) => {
      const str =
        typeof data === "string" ? data : new TextDecoder().decode(data);
      return new TextEncoder().encode(`hashed-${alg}-${str}`);
    }),
    verifyJwt: vi.fn(async () => ({
      signerJwk: mockJwk,
      verified: true,
    })),
  };

  const mockAuthorizationServerMetadata = {
    issuer: "https://auth.example.com",
  } as AuthorizationServerMetadata;

  const mockConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  }) as IoWalletSdkConfig;

  const mockAuthorizationRequest = {
    client_id: "client-123",
  };

  const createMockClientAttestationJwt = (payload: Record<string, unknown>) =>
    [
      encodeToBase64Url(
        JSON.stringify({
          alg: "ES256",
          kid: "test-kid",
          trust_chain: ["dummy.jwt.token"],
          typ: "oauth-client-attestation+jwt",
        }),
      ),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  const createMockClientAttestationPopJwt = (
    payload: Record<string, unknown>,
  ) =>
    [
      encodeToBase64Url(
        JSON.stringify({
          alg: "ES256",
          typ: "oauth-client-attestation-pop+jwt",
        }),
      ),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  const createMockDpopJwt = (payload: Record<string, unknown>) =>
    [
      encodeToBase64Url(
        JSON.stringify({ alg: "ES256", jwk: mockJwk, typ: "dpop+jwt" }),
      ),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  describe("DPoP verification", () => {
    it("should verify authorization request with valid DPoP", async () => {
      const dpopJwt = createMockDpopJwt({
        ath: "test-access-token-hash",
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwk).toEqual(mockJwk);
      expect(result.dpop?.jwkThumbprint).toBeDefined();
      expect(typeof result.dpop?.jwkThumbprint).toBe("string");
    });

    it("should throw error when DPoP is required but not provided", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          required: true,
        },
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /Missing required DPoP parameters/,
      );
    });

    it("should return undefined dpop when not provided and not required", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should verify DPoP with allowed signing algorithms", async () => {
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          allowedSigningAlgs: ["ES256", "RS256"],
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwkThumbprint).toBeDefined();
    });
  });

  describe("Client attestation verification", () => {
    it("should verify authorization request with valid client attestation", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationPop).toBeDefined();
    });

    it("should throw error when client attestation JWTs are not provided", async () => {
      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt: "",
          walletAttestationJwt: "",
        },
        config: mockConfig,
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });

    it("should throw error when only clientAttestationJwt is provided", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt: "",
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });

    it("should throw error when only clientAttestationPopJwt is provided", async () => {
      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: "",
        },
        config: mockConfig,
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });

    it("should throw error when client_id does not match between request and attestation", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "different-client-id",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "different-client-id",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: { client_id: "client-123" },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /does not match the client id/,
      );
    });

    it("should verify when client attestation is provided", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.clientAttestation).toBeDefined();
    });
  });

  describe("DPoP and client attestation key matching", () => {
    it("should verify when confirmation key matches DPoP key", async () => {
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          ensureConfirmationKeyMatchesDpopKey: true,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should throw error when confirmation key does not match DPoP key", async () => {
      const differentJwk: Jwk = {
        crv: "P-256",
        kty: "EC",
        x: "different-x",
        y: "different-y",
      };

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: differentJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          ensureConfirmationKeyMatchesDpopKey: true,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAuthorizationRequest(options)).rejects.toThrow(
        /DPoP JWK thumbprint value to match/,
      );
    });

    it("should not validate key matching when ensureConfirmationKeyMatchesDpopKey is false", async () => {
      const differentJwk: Jwk = {
        crv: "P-256",
        kty: "EC",
        x: "different-x",
        y: "different-y",
      };

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: differentJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          ensureConfirmationKeyMatchesDpopKey: false,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });

  describe("Combined scenarios", () => {
    it("should verify authorization request with both DPoP and client attestation", async () => {
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwk).toEqual(mockJwk);
      expect(result.dpop?.jwkThumbprint).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationPop).toBeDefined();
    });

    it("should use custom date for time-based validation", async () => {
      const customDate = new Date("2024-01-01T00:00:00Z");
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(customDate.getTime() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(customDate.getTime() / 1000) + 3600,
        iat: Math.floor(customDate.getTime() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(customDate.getTime() / 1000) + 3600,
        iat: Math.floor(customDate.getTime() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        now: customDate,
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
    });

    it("should work without client_id in authorization request", async () => {
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
        aal: "high",
        cnf: { jwk: mockJwk },
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "https://issuer.example.com",
        sub: "client-123",
      });

      const clientAttestationPopJwt = createMockClientAttestationPopJwt({
        aud: "https://auth.example.com",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        jti: "test-jti",
      });

      const options: VerifyAuthorizationRequestOptions = {
        authorizationRequest: {},
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
        },
        config: mockConfig,
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyAuthorizationRequest(options);

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });
});
