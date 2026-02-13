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
import { PkceCodeChallengeMethod } from "../../pkce";
import {
  VerifyAccessTokenRequestOptions,
  verifyAccessTokenRequest,
} from "../verify-access-token-request";

describe("verifyAuthorizationCodeTokenRequest", () => {
  const mockJwk: Jwk = {
    crv: "P-256",
    kty: "EC",
    x: "test-x",
    y: "test-y",
  };

  const mockRequest: RequestLike = {
    headers: new Headers(),
    method: "POST",
    url: "https://auth.example.com/token",
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

  const mockAccessTokenRequest = {
    code: "test-auth-code",
    code_verifier: "test-code-verifier",
    grant_type: "authorization_code" as const,
    redirect_uri: "https://client.example.com/callback",
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

  // The mock hash function produces "hashed-sha-256-{input}" as bytes
  // For codeVerifier "test-code-verifier", the derived code challenge when base64url encoded is:
  const mockS256CodeChallenge = "aGFzaGVkLXNoYS0yNTYtdGVzdC1jb2RlLXZlcmlmaWVy";

  const createValidOptions = (
    overrides?: Partial<VerifyAccessTokenRequestOptions>,
  ): VerifyAccessTokenRequestOptions => {
    const now = new Date();
    const dpopJwt = createMockDpopJwt({
      htm: "POST",
      htu: "https://auth.example.com/token",
      iat: Math.floor(now.getTime() / 1000),
      jti: "test-jti",
    });

    const clientAttestationJwt = createMockClientAttestationJwt({
      aal: "high",
      cnf: { jwk: mockJwk },
      exp: Math.floor(now.getTime() / 1000) + 3600,
      iat: Math.floor(now.getTime() / 1000),
      iss: "https://issuer.example.com",
      sub: "client-123",
    });

    const clientAttestationPopJwt = createMockClientAttestationPopJwt({
      aud: "https://auth.example.com",
      exp: Math.floor(now.getTime() / 1000) + 3600,
      iat: Math.floor(now.getTime() / 1000),
      iss: "client-123",
      jti: "test-jti",
    });

    return {
      accessTokenRequest: mockAccessTokenRequest,
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: mockCallbacks,
      clientAttestation: {
        clientAttestationJwt,
        clientAttestationPopJwt,
      },
      config: mockConfig,
      dpop: {
        jwt: dpopJwt,
      },
      expectedCode: "test-auth-code",
      grant: {
        code: "test-auth-code",
        grantType: "authorization_code",
      },
      now,
      pkce: {
        codeChallenge: mockS256CodeChallenge,
        codeChallengeMethod: PkceCodeChallengeMethod.S256,
        codeVerifier: "test-code-verifier",
      },
      request: mockRequest,
      ...overrides,
    };
  };

  describe("Successful verification", () => {
    it("should verify authorization code token request with all valid inputs", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
      expect(result.dpop).toBeDefined();
      expect(result.dpop.jwk).toEqual(mockJwk);
      expect(result.dpop.jwkThumbprint).toBeDefined();
      expect(typeof result.dpop.jwkThumbprint).toBe("string");
      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation.clientAttestation).toBeDefined();
      expect(result.clientAttestation.clientAttestationPop).toBeDefined();
    });

    it("should verify with optional codeExpiresAt when code is not expired", async () => {
      const now = new Date();
      const codeExpiresAt = new Date(now.getTime() + 600000); // 10 minutes from now

      const options = createValidOptions({
        codeExpiresAt,
        now,
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should verify with allowed signing algorithms for DPoP", async () => {
      const options = createValidOptions({
        dpop: {
          allowedSigningAlgs: ["ES256", "RS256"],
          jwt: createMockDpopJwt({
            htm: "POST",
            htu: "https://auth.example.com/token",
            iat: Math.floor(Date.now() / 1000),
            jti: "test-jti",
          }),
        },
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
      expect(result.dpop.jwkThumbprint).toBeDefined();
    });

    it("should use current date when now is not provided", async () => {
      const options = createValidOptions();
      delete (options as Partial<VerifyAccessTokenRequestOptions>).now;

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });
  });

  describe("Authorization code validation", () => {
    it("should throw error when authorization code does not match expected code", async () => {
      const options = createValidOptions({
        expectedCode: "expected-code",
        grant: {
          code: "different-code",
          grantType: "authorization_code",
        },
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Invalid 'code' provided",
      );
    });

    it("should throw error when authorization code is expired", async () => {
      const now = new Date();
      const codeExpiresAt = new Date(now.getTime() - 1000); // 1 second ago

      const options = createValidOptions({
        codeExpiresAt,
        now,
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'code' provided",
      );
    });

    it("should not check expiration when codeExpiresAt is not provided", async () => {
      const options = createValidOptions();
      delete (options as Partial<VerifyAccessTokenRequestOptions>)
        .codeExpiresAt;

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });

    it("should pass when code expires exactly at now", async () => {
      const now = new Date();
      const codeExpiresAt = new Date(now.getTime() + 1); // 1ms after now

      const options = createValidOptions({
        codeExpiresAt,
        now,
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });
  });

  describe("PKCE verification", () => {
    it("should verify PKCE with S256 code challenge method", async () => {
      const options = createValidOptions({
        pkce: {
          codeChallenge: mockS256CodeChallenge,
          codeChallengeMethod: PkceCodeChallengeMethod.S256,
          codeVerifier: "test-code-verifier",
        },
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });

    it("should verify PKCE with plain code challenge method", async () => {
      const options = createValidOptions({
        pkce: {
          codeChallenge: "plain-verifier",
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
          codeVerifier: "plain-verifier",
        },
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });
  });

  describe("DPoP verification", () => {
    it("should extract JWK from DPoP header", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result.dpop.jwk).toEqual(mockJwk);
    });

    it("should extract JWK thumbprint from DPoP", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result.dpop.jwkThumbprint).toBeDefined();
      expect(typeof result.dpop.jwkThumbprint).toBe("string");
      expect(result.dpop.jwkThumbprint.length).toBeGreaterThan(0);
    });
  });

  describe("Client attestation verification", () => {
    it("should verify client attestation JWT", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result.clientAttestation.clientAttestation).toBeDefined();
      expect(result.clientAttestation.clientAttestation.payload).toBeDefined();
    });

    it("should verify client attestation PoP JWT", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result.clientAttestation.clientAttestationPop).toBeDefined();
      expect(
        result.clientAttestation.clientAttestationPop.payload,
      ).toBeDefined();
    });

    it("should throw error when client attestation JWT is missing", async () => {
      const options = createValidOptions({
        clientAttestation: {
          clientAttestationJwt: "",
          clientAttestationPopJwt: createMockClientAttestationPopJwt({
            aud: "https://auth.example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            iss: "client-123",
            jti: "test-jti",
          }),
        },
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });

    it("should throw error when client attestation PoP JWT is missing", async () => {
      const options = createValidOptions({
        clientAttestation: {
          clientAttestationJwt: createMockClientAttestationJwt({
            aal: "high",
            cnf: { jwk: mockJwk },
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            iss: "https://issuer.example.com",
            sub: "client-123",
          }),
          clientAttestationPopJwt: "",
        },
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });
  });

  describe("Custom date/time handling", () => {
    it("should use custom date for time-based validation", async () => {
      const customDate = new Date("2024-06-01T12:00:00Z");
      const codeExpiresAt = new Date("2024-06-01T12:30:00Z");

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/token",
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

      const options = createValidOptions({
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        codeExpiresAt,
        dpop: {
          jwt: dpopJwt,
        },
        now: customDate,
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });

    it("should fail when code is expired at custom date", async () => {
      const customDate = new Date("2024-06-01T12:00:00Z");
      const codeExpiresAt = new Date("2024-06-01T11:00:00Z"); // 1 hour before

      const options = createValidOptions({
        codeExpiresAt,
        now: customDate,
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'code' provided",
      );
    });
  });

  describe("Result structure", () => {
    it("should return correct result structure", async () => {
      const options = createValidOptions();

      const result = await verifyAccessTokenRequest(options);

      expect(result).toHaveProperty("clientAttestation");
      expect(result).toHaveProperty("dpop");
      expect(result.clientAttestation).toHaveProperty("clientAttestation");
      expect(result.clientAttestation).toHaveProperty("clientAttestationPop");
      expect(result.dpop).toHaveProperty("jwk");
      expect(result.dpop).toHaveProperty("jwkThumbprint");
    });

    it("should return JWK as provided in DPoP header", async () => {
      const customJwk: Jwk = {
        crv: "P-384",
        kty: "EC",
        x: "custom-x-value",
        y: "custom-y-value",
      };

      const dpopJwt = [
        encodeToBase64Url(
          JSON.stringify({ alg: "ES384", jwk: customJwk, typ: "dpop+jwt" }),
        ),
        encodeToBase64Url(
          JSON.stringify({
            htm: "POST",
            htu: "https://auth.example.com/token",
            iat: Math.floor(Date.now() / 1000),
            jti: "test-jti",
          }),
        ),
        "signature",
      ].join(".");

      const options = createValidOptions({
        dpop: {
          allowedSigningAlgs: ["ES384"],
          jwt: dpopJwt,
        },
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result.dpop.jwk).toEqual(customJwk);
    });
  });

  describe("Edge cases", () => {
    it("should handle exact expiration boundary", async () => {
      const now = new Date("2024-06-01T12:00:00.000Z");
      const codeExpiresAt = new Date("2024-06-01T12:00:00.000Z"); // Same time

      const options = createValidOptions({
        codeExpiresAt,
        now,
      });

      // When now.getTime() equals codeExpiresAt.getTime(), it should NOT be expired
      // (now > codeExpiresAt is false when equal)
      const result = await verifyAccessTokenRequest(options);
      expect(result).toBeDefined();
    });

    it("should handle millisecond precision in expiration check", async () => {
      const now = new Date("2024-06-01T12:00:00.001Z");
      const codeExpiresAt = new Date("2024-06-01T12:00:00.000Z");

      const options = createValidOptions({
        codeExpiresAt,
        now,
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'code' provided",
      );
    });
  });
});
