/* eslint-disable max-lines-per-function */
import {
  type CallbackContext,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  Jwk,
  RequestLike,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import type { BaseAuthorizationServerMetadata } from "../../authorization-server-metadata";

import { Oauth2Error } from "../../errors";
import { PkceCodeChallengeMethod } from "../../pkce";
import { VerifyPreAuthorizedCodeAccessTokenRequestOptions } from "../APTITUDE/verify-access-token-request";
import { preAuthorizedCodeGrantIdentifier } from "../APTITUDE/z-grant-types";
import {
  VerifyAccessTokenRequestOptions,
  verifyAccessTokenRequest,
} from "../verify-access-token-request";

describe("verifyAccessTokenRequest", () => {
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
  } as BaseAuthorizationServerMetadata;

  const v1_0Config = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  });

  const aptitudeConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.APTITUDE,
  });

  const mockAccessTokenRequest = {
    code: "test-auth-code",
    code_verifier: "test-code-verifier",
    grant_type: "authorization_code" as const,
    redirect_uri: "https://client.example.com/callback",
  };

  const createMockWalletAttestationJwt = (payload: Record<string, unknown>) =>
    [
      encodeToBase64Url(
        JSON.stringify({
          alg: "ES256",
          kid: "test-kid",
          trust_chain: ["dummy.jwt.token"],
          typ: "oauth-client-attestation+jwt",
          x5c: [
            "MIICrDCCAlKgAwIBAgIUCQ5zD8eGxAN6c5isgQk0jkp3qzwwCgYIKoZIzj0EAwIwgZIxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVMYXppbzENMAsGA1UEBwwEUm9tYTEWMBQGA1UECgwNUGFnb1BBIFMucC5BLjEkMCIGA1UEAwwbZm9vMTEuYmxvYi5jb3JlLndpbmRvd3MubmV0MSYwJAYJKoZIhvcNAQkBFhdwYWdvcGFzcGFAcGVjLnBhZ29wYS5pdDAeFw0yNTA3MDMxNTE2NTlaFw0yNjA3MDMxNTE2NTlaMIGSMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFTGF6aW8xDTALBgNVBAcMBFJvbWExFjAUBgNVBAoMDVBhZ29QQSBTLnAuQS4xJDAiBgNVBAMMG2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldDEmMCQGCSqGSIb3DQEJARYXcGFnb3Bhc3BhQHBlYy5wYWdvcGEuaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtdnuBd5hAg3cPyz7/o8vBFyL4sp45HikFogMZse7f9/iL4gn6YM/ehP1CQI0dFnT3c/RdxFyRukKWXscopwXso4GDMIGAMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMCYGA1UdEQQfMB2CG2ZvbzExLmJsb2IuY29yZS53aW5kb3dzLm5ldDAdBgNVHQ4EFgQUOd7M/0bo1+saPT/H9M+G96sKnYIwHwYDVR0jBBgwFoAUkKHxQLaudIm0WfwZeN5HMTG8SCMwCgYIKoZIzj0EAwIDSAAwRQIgSXKs9Gx2bXVG9nxap1I/KqwHdh6SQDKI85J9n7FqrI8CIQCqltHTw6sci1R4RSOFySEvzEohQTbNTke+X2lD9iQd5A==",
          ],
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

    const clientAttestationJwt = createMockWalletAttestationJwt({
      aal: "high",
      cnf: { jwk: mockJwk },
      exp: Math.floor(now.getTime() / 1000) + 3600,
      iat: Math.floor(now.getTime() / 1000),
      iss: "https://issuer.example.com",
      sub: "client-123",
      wallet_link: "https://example.org/wallets/ExampleOrg/info",
      wallet_name: "ExampleOrg",
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
        clientAttestationPopJwt,
        walletAttestationJwt: clientAttestationJwt,
      },
      config: v1_0Config,
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

  describe("Pre-authorized code grant", () => {
    const createPreAuthorizedOptions = (
      overrides: Partial<VerifyPreAuthorizedCodeAccessTokenRequestOptions> = {},
    ): VerifyPreAuthorizedCodeAccessTokenRequestOptions => {
      const common = createValidOptions();
      return {
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          "pre-authorized_code": "issuer-pre-authorized-code",
        },
        authorizationServerMetadata: common.authorizationServerMetadata,
        callbacks: common.callbacks,
        clientAttestation: common.clientAttestation,
        config: aptitudeConfig,
        dpop: common.dpop,
        expectedPreAuthorizedCode: "issuer-pre-authorized-code",
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: "issuer-pre-authorized-code",
        },
        now: common.now,
        request: common.request,
        ...overrides,
      };
    };

    it.each([undefined, "001234", "A+%&= code"])(
      "verifies transaction code %s without PKCE and retains verified security proofs",
      async (txCode) => {
        const options = createPreAuthorizedOptions({ expectedTxCode: txCode });
        options.accessTokenRequest.tx_code = txCode;
        options.grant.txCode = txCode;

        const result = await verifyAccessTokenRequest(options);

        expect(options).not.toHaveProperty("pkce");
        expect(result.dpop.jwk).toEqual(mockJwk);
        expect(result.dpop.jwkThumbprint).toEqual(expect.any(String));
        expect(result.clientAttestation.clientAttestation.payload.sub).toBe(
          "client-123",
        );
        expect(result.clientAttestation.clientAttestationPop.payload.iss).toBe(
          "client-123",
        );
      },
    );

    it.each(["different-issued-code", ""])(
      "rejects a pre-authorized code when the stored expected value is %s",
      async (expectedPreAuthorizedCode) => {
        const options = createPreAuthorizedOptions({
          expectedPreAuthorizedCode,
        });

        await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
          "Invalid 'pre-authorized_code' provided",
        );
      },
    );

    it("rejects a body code that differs from the parsed grant", async () => {
      const options = createPreAuthorizedOptions();
      options.accessTokenRequest["pre-authorized_code"] = "different-body-code";

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Invalid 'pre-authorized_code' provided",
      );
    });

    it("rejects a mismatched grant type", async () => {
      const options = createPreAuthorizedOptions();
      options.accessTokenRequest =
        mockAccessTokenRequest as unknown as VerifyPreAuthorizedCodeAccessTokenRequestOptions["accessTokenRequest"];

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Grant type does not match the access token request",
      );
    });

    it("accepts a code before its expiration", async () => {
      const options = createPreAuthorizedOptions();
      options.preAuthorizedCodeExpiresAt = new Date(
        (options.now ?? new Date()).getTime() + 60000,
      );

      await expect(verifyAccessTokenRequest(options)).resolves.toHaveProperty(
        "dpop",
      );
    });

    it("rejects an expired code using the supplied clock", async () => {
      const options = createPreAuthorizedOptions();
      options.preAuthorizedCodeExpiresAt = new Date(
        (options.now ?? new Date()).getTime() - 1,
      );

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'pre-authorized_code' provided",
      );
    });

    it("checks expiration using the current time when now is omitted", async () => {
      const options = createPreAuthorizedOptions({
        now: undefined,
        preAuthorizedCodeExpiresAt: new Date(Date.now() - 60000),
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'pre-authorized_code' provided",
      );
    });

    it("rejects an invalid expiration date", async () => {
      const options = createPreAuthorizedOptions({
        preAuthorizedCodeExpiresAt: new Date("invalid"),
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Invalid expiration date for 'pre-authorized_code'",
      );
    });

    it.each([
      {
        expectedTxCode: "001234",
        label: "missing",
        message: "Missing required 'tx_code' in request",
        txCode: undefined,
      },
      {
        expectedTxCode: undefined,
        label: "unexpected",
        message: "Request contains 'tx_code' that was not expected",
        txCode: "001234",
      },
      {
        expectedTxCode: "001234",
        label: "incorrect",
        message: "Invalid 'tx_code' provided",
        txCode: "009999",
      },
      {
        expectedTxCode: "001234",
        label: "without leading zeros",
        message: "Invalid 'tx_code' provided",
        txCode: "1234",
      },
    ])(
      "rejects a $label transaction code",
      async ({ expectedTxCode, message, txCode }) => {
        const options = createPreAuthorizedOptions({ expectedTxCode });
        options.accessTokenRequest.tx_code = txCode;
        options.grant.txCode = txCode;

        await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
          message,
        );
      },
    );

    it("rejects a transaction code that differs between the body and parsed grant", async () => {
      const options = createPreAuthorizedOptions({ expectedTxCode: "001234" });
      options.accessTokenRequest.tx_code = "009999";
      options.grant.txCode = "001234";

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Transaction code does not match the access token request",
      );
    });

    it.each(["", "invalid-jwt"])(
      "rejects an invalid DPoP proof: %s",
      async (jwt) => {
        const options = createPreAuthorizedOptions({ dpop: { jwt } });

        await expect(verifyAccessTokenRequest(options)).rejects.toThrow();
      },
    );

    it("still rejects an incorrect DPoP nonce", async () => {
      const options = createPreAuthorizedOptions();
      options.dpop = {
        expectedNonce: "expected-nonce",
        jwt: createMockDpopJwt({
          htm: "POST",
          htu: mockRequest.url,
          iat: Math.floor((options.now ?? new Date()).getTime() / 1000),
          jti: "pre-authorized-dpop-jti",
          nonce: "wrong-nonce",
        }),
      };

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        /expected nonce value/,
      );
    });

    it.each(["walletAttestationJwt", "clientAttestationPopJwt"] as const)(
      "still requires %s",
      async (field) => {
        const options = createPreAuthorizedOptions();
        options.clientAttestation[field] = "";

        await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
          /Missing required client attestation parameters/,
        );
      },
    );
  });

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

    it("should pass when dpop.expectedNonce matches the nonce in the DPoP proof", async () => {
      const now = new Date();
      const nonce = "server-nonce-abc123";
      const options = createValidOptions({
        dpop: {
          expectedNonce: nonce,
          jwt: createMockDpopJwt({
            htm: "POST",
            htu: "https://auth.example.com/token",
            iat: Math.floor(now.getTime() / 1000),
            jti: "test-jti",
            nonce,
          }),
        },
        now,
      });

      const result = await verifyAccessTokenRequest(options);

      expect(result).toBeDefined();
    });

    it("should throw when dpop.expectedNonce does not match the nonce in the DPoP proof", async () => {
      const now = new Date();
      const options = createValidOptions({
        dpop: {
          expectedNonce: "server-nonce-abc123",
          jwt: createMockDpopJwt({
            htm: "POST",
            htu: "https://auth.example.com/token",
            iat: Math.floor(now.getTime() / 1000),
            jti: "test-jti",
            nonce: "wrong-nonce",
          }),
        },
        now,
      });

      const result = verifyAccessTokenRequest(options);

      await expect(result).rejects.toThrow(Oauth2Error);
      await expect(result).rejects.toThrow(/expected nonce value/);
    });

    it("should throw when dpop.expectedNonce is empty", async () => {
      const options = createValidOptions({
        dpop: {
          expectedNonce: "",
          jwt: createMockDpopJwt({
            htm: "POST",
            htu: "https://auth.example.com/token",
            iat: Math.floor(Date.now() / 1000),
            jti: "test-jti",
          }),
        },
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Invalid 'dpop.expectedNonce' provided",
      );
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
          clientAttestationPopJwt: createMockClientAttestationPopJwt({
            aud: "https://auth.example.com",
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            iss: "client-123",
            jti: "test-jti",
          }),
          walletAttestationJwt: "",
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
          clientAttestationPopJwt: "",
          walletAttestationJwt: createMockWalletAttestationJwt({
            aal: "high",
            cnf: { jwk: mockJwk },
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            iss: "https://issuer.example.com",
            sub: "client-123",
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

      const clientAttestationJwt = createMockWalletAttestationJwt({
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
          clientAttestationPopJwt,
          walletAttestationJwt: clientAttestationJwt,
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

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/token",
        iat: Math.floor(customDate.getTime() / 1000),
        jti: "test-jti",
      });

      const options = createValidOptions({
        codeExpiresAt,
        dpop: {
          jwt: dpopJwt,
        },
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

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/token",
        iat: Math.floor(now.getTime() / 1000),
        jti: "test-jti",
      });

      const options = createValidOptions({
        codeExpiresAt,
        dpop: {
          jwt: dpopJwt,
        },
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

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/token",
        iat: Math.floor(now.getTime() / 1000),
        jti: "test-jti",
      });

      const options = createValidOptions({
        codeExpiresAt,
        dpop: {
          jwt: dpopJwt,
        },
        now,
      });

      await expect(verifyAccessTokenRequest(options)).rejects.toThrow(
        "Expired 'code' provided",
      );
    });
  });
});
