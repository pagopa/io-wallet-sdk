/* eslint-disable max-lines-per-function */
import {
  AuthorizationServerMetadata,
  CallbackContext,
  Jwk,
  JwtSigner,
  Oauth2Error,
} from "@openid4vc/oauth2";
import { encodeToBase64Url } from "@openid4vc/utils";
import { RequestLike } from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import {
  VerifyPushedAuthorizationRequestOptions,
  verifyPushedAuthorizationRequest,
} from "../verify-pushed-authorization-request";

describe("verifyPushedAuthorizationRequest", () => {
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

  const mockAuthorizationRequest = {
    client_id: "client-123",
  };

  const mockJwtSigner = {
    alg: "ES256",
    publicJwk: mockJwk,
  } as JwtSigner;

  const createMockJwt = (
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
  ) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  const createMockClientAttestationJwt = (payload: Record<string, unknown>) =>
    createMockJwt(
      { alg: "ES256", typ: "oauth-client-attestation+jwt" },
      payload,
    );

  const createMockClientAttestationPopJwt = (
    payload: Record<string, unknown>,
  ) =>
    createMockJwt(
      { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" },
      payload,
    );

  const createMockDpopJwt = (payload: Record<string, unknown>) =>
    createMockJwt({ alg: "ES256", jwk: mockJwk, typ: "dpop+jwt" }, payload);

  const createMockJarJwt = (payload: Record<string, unknown>) =>
    createMockJwt({ alg: "ES256", typ: "oauth-authz-req+jwt" }, payload);

  describe("JAR request verification", () => {
    it("should verify pushed authorization request with JAR", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        response_type: "code",
        scope: "openid",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.jar?.authorizationRequestPayload).toBeDefined();
      expect(result.jar?.authorizationRequestPayload.client_id).toBe(
        "client-123",
      );
      expect(result.jar?.signer).toBeDefined();
    });

    it("should verify pushed authorization request without JAR", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeUndefined();
      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should verify JAR with complex authorization request payload", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        code_challenge: "test-challenge",
        code_challenge_method: "S256",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        redirect_uri: "https://client.example.com/callback",
        response_type: "code",
        scope: "openid profile email",
        state: "test-state",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.jar?.authorizationRequestPayload.code_challenge).toBe(
        "test-challenge",
      );
      expect(result.jar?.authorizationRequestPayload.scope).toBe(
        "openid profile email",
      );
    });
  });

  describe("JAR with DPoP", () => {
    it("should verify pushed authorization request with JAR and DPoP", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwk).toEqual(mockJwk);
      expect(result.dpop?.jwkThumbprint).toBeDefined();
    });

    it("should verify with JAR, DPoP as required", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          jwt: dpopJwt,
          required: true,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.dpop).toBeDefined();
    });

    it("should throw error when DPoP is required but not provided even with JAR", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          required: true,
        },
        request: mockRequest,
      };

      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        /Missing required DPoP parameters/,
      );
    });
  });

  describe("JAR with client attestation", () => {
    it("should verify pushed authorization request with JAR and client attestation", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationPop).toBeDefined();
    });

    it("should throw error when client attestation JWTs are not provided even with JAR", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt: "",
          clientAttestationPopJwt: "",
        },
        request: mockRequest,
      };

      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        /Missing required client attestation parameters/,
      );
    });
  });

  describe("Complete verification flow", () => {
    it("should verify pushed authorization request with JAR, DPoP, and client attestation", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
        scope: "openid",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.jar?.authorizationRequestPayload.scope).toBe("openid");
      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwk).toEqual(mockJwk);
      expect(result.dpop?.jwkThumbprint).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationPop).toBeDefined();
    });

    it("should verify with all components and ensureConfirmationKeyMatchesDpopKey enabled", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
          ensureConfirmationKeyMatchesDpopKey: true,
        },
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should throw when key matching fails with all components present", async () => {
      const differentJwk: Jwk = {
        crv: "P-256",
        kty: "EC",
        x: "different-x",
        y: "different-y",
      };

      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
          ensureConfirmationKeyMatchesDpopKey: true,
        },
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        Oauth2Error,
      );
      await expect(verifyPushedAuthorizationRequest(options)).rejects.toThrow(
        /DPoP JWK thumbprint value to match/,
      );
    });
  });

  describe("Time-based validation", () => {
    it("should use custom date for time-based validation with JAR", async () => {
      const customDate = new Date("2024-01-01T00:00:00Z");
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(customDate.getTime() / 1000),
        iss: "client-123",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        now: customDate,
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
    });

    it("should propagate custom date to DPoP and client attestation verification", async () => {
      const customDate = new Date("2024-01-01T00:00:00Z");

      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(customDate.getTime() / 1000),
        iss: "client-123",
      });

      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(customDate.getTime() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          jwt: dpopJwt,
        },
        now: customDate,
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });

  describe("Edge cases", () => {
    it("should work with minimal authorization request when JAR is provided", async () => {
      const jarJwt = createMockJarJwt({
        aud: "https://auth.example.com",
        client_id: "client-123",
        iat: Math.floor(Date.now() / 1000),
        iss: "client-123",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: { client_id: "client-123" },
        authorizationRequestJwt: {
          jwt: jarJwt,
          signer: mockJwtSigner,
        },
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeDefined();
      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should handle request with DPoP and client attestation (no JAR)", async () => {
      const dpopJwt = createMockDpopJwt({
        htm: "POST",
        htu: "https://auth.example.com/par",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
      });

      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        dpop: {
          jwt: dpopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeUndefined();
      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should handle request with client attestation (no JAR or DPoP)", async () => {
      const clientAttestationJwt = createMockClientAttestationJwt({
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

      const options: VerifyPushedAuthorizationRequestOptions = {
        authorizationRequest: mockAuthorizationRequest,
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: mockCallbacks,
        clientAttestation: {
          clientAttestationJwt,
          clientAttestationPopJwt,
        },
        request: mockRequest,
      };

      const result = await verifyPushedAuthorizationRequest(options);

      expect(result.jar).toBeUndefined();
      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });
});
