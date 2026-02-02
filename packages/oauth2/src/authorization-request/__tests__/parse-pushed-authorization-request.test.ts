/* eslint-disable max-lines-per-function */
import { RequestLike } from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oauth2Error } from "../../errors";
import { parsePushedAuthorizationRequest } from "../parse-pushed-authorization-request";

describe("parsePushedAuthorizationRequest", () => {
  const mockFetch = vi.fn();
  const mockRequest: RequestLike = {
    headers: new Headers(),
    method: "POST",
    url: "https://issuer.example.com",
  };

  const baseAuthorizationRequest = {
    authorization_details: [
      {
        credential_configuration_id: "test-config",
        type: "openid_credential" as const,
      },
    ],
    client_id: "test-client-id",
    code_challenge: "test-challenge",
    code_challenge_method: "S256",
    redirect_uri: "https://client.example.com/callback",
    response_mode: "form_post",
    response_type: "code",
    state: "test-state",
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Plain authorization request", () => {
    it("should parse a valid plain authorization request", async () => {
      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: baseAuthorizationRequest,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toEqual(baseAuthorizationRequest);
      expect(result.authorizationRequestJwt).toBeUndefined();
    });

    it("should parse authorization request with scope instead of authorization_details", async () => {
      const authRequestWithScope = {
        client_id: "test-client-id",
        code_challenge: "test-challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_mode: "form_post",
        response_type: "code",
        scope: "openid profile",
        state: "test-state",
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: authRequestWithScope,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toEqual(authRequestWithScope);
      expect(result.authorizationRequestJwt).toBeUndefined();
    });

    it("should throw error for missing mandatory fields", async () => {
      const invalidRequest = {
        client_id: "test-client-id",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: invalidRequest,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow();
    });

    it("should throw error when neither authorization_details nor scope is provided", async () => {
      const requestWithoutAuthDetailsOrScope = {
        client_id: "test-client-id",
        code_challenge: "test-challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_mode: "form_post",
        response_type: "code",
        state: "test-state",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: requestWithoutAuthDetailsOrScope,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow();
    });
  });

  describe("JAR (JWT-secured Authorization Request)", () => {
    it("should parse a JAR request with request parameter (by value)", async () => {
      const mockJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6InRlc3QtY2xpZW50LWlkIiwiY29kZV9jaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFjayIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJzdGF0ZSI6InRlc3Qtc3RhdGUiLCJzY29wZSI6Im9wZW5pZCJ9.signature";

      const jarRequest = {
        client_id: "test-client-id",
        request: mockJwt,
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: jarRequest,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toBeDefined();
      expect(result.authorizationRequestJwt).toBe(mockJwt);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("should parse a JAR request with request_uri parameter (by reference)", async () => {
      const mockJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6InRlc3QtY2xpZW50LWlkIiwiY29kZV9jaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFjayIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJzdGF0ZSI6InRlc3Qtc3RhdGUiLCJzY29wZSI6Im9wZW5pZCJ9.signature";

      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => mockJwt,
      });

      const jarRequest = {
        client_id: "test-client-id",
        request_uri: "https://issuer.example.com/request/abc123",
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: jarRequest,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toBeDefined();
      expect(result.authorizationRequestJwt).toBeDefined();
      expect(mockFetch).toHaveBeenCalledWith(
        "https://issuer.example.com/request/abc123",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });

    it("should throw error for JAR request with invalid JWT payload structure", async () => {
      const invalidJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpbnZhbGlkIjoicGF5bG9hZCJ9.signature";

      const jarRequest = {
        client_id: "test-client-id",
        request: invalidJwt,
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: jarRequest,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow();
    });

    it("should handle JAR request with both authorization_details and scope", async () => {
      const jarRequestJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6InRlc3QtY2xpZW50LWlkIiwiY29kZV9jaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFjayIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJzdGF0ZSI6InRlc3Qtc3RhdGUiLCJhdXRob3JpemF0aW9uX2RldGFpbHMiOlt7InR5cGUiOiJvcGVuaWRfY3JlZGVudGlhbCIsImNyZWRlbnRpYWxfY29uZmlndXJhdGlvbl9pZCI6InRlc3QtY29uZmlnIn1dLCJzY29wZSI6Im9wZW5pZCJ9.signature";

      const jarRequest = {
        client_id: "test-client-id",
        request: jarRequestJwt,
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: jarRequest,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toBeDefined();
      expect(result.authorizationRequestJwt).toBe(jarRequestJwt);
    });
  });

  describe("Error handling", () => {
    it("should throw error when request_uri fetch fails", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const jarRequest = {
        client_id: "test-client-id",
        request_uri: "https://issuer.example.com/request/invalid",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: jarRequest,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow(Oauth2Error);
    });

    it("should throw error for invalid authorization request structure", async () => {
      const invalidRequest = {
        authorization_details: "not-an-array",
        client_id: "test-client-id",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: invalidRequest,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow();
    });

    it("should throw error when parseAuthorizationRequest throws", async () => {
      const headers = new Headers();
      headers.set("DPoP", "invalid-dpop");

      const requestWithInvalidDpop: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: baseAuthorizationRequest,
          callbacks: { fetch: mockFetch },
          request: requestWithInvalidDpop,
        }),
      ).rejects.toThrow(Oauth2Error);
    });

    it("should throw error when both request and request_uri are present", async () => {
      const jarRequest = {
        client_id: "test-client-id",
        request: "jwt-token",
        request_uri: "https://issuer.example.com/request/abc123",
      };

      await expect(
        parsePushedAuthorizationRequest({
          authorizationRequest: jarRequest,
          callbacks: { fetch: mockFetch },
          request: mockRequest,
        }),
      ).rejects.toThrow(Oauth2Error);
    });
  });

  describe("Integration scenarios", () => {
    it("should parse JAR request and extract client attestation from headers", async () => {
      const headers = new Headers();
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const requestWithHeaders: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com",
      };

      const mockJwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6InRlc3QtY2xpZW50LWlkIiwiY29kZV9jaGFsbGVuZ2UiOiJ0ZXN0LWNoYWxsZW5nZSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFjayIsInJlc3BvbnNlX21vZGUiOiJmb3JtX3Bvc3QiLCJzdGF0ZSI6InRlc3Qtc3RhdGUiLCJzY29wZSI6Im9wZW5pZCJ9.signature";

      const jarRequest = {
        client_id: "test-client-id",
        request: mockJwt,
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: jarRequest,
        callbacks: { fetch: mockFetch },
        request: requestWithHeaders,
      });

      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationJwt).toBe(
        headers.get("OAuth-Client-Attestation"),
      );
      expect(result.clientAttestation?.clientAttestationPopJwt).toBe(
        headers.get("OAuth-Client-Attestation-PoP"),
      );
    });

    it("should parse plain request with all optional fields", async () => {
      const fullAuthRequest = {
        ...baseAuthorizationRequest,
        issuer_state: "issuer-state-value",
        scope: "openid profile",
      };

      const result = await parsePushedAuthorizationRequest({
        authorizationRequest: fullAuthRequest,
        callbacks: { fetch: mockFetch },
        request: mockRequest,
      });

      expect(result.authorizationRequest).toEqual(fullAuthRequest);
      expect(result.authorizationRequestJwt).toBeUndefined();
    });
  });
});
