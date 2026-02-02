/* eslint-disable max-lines-per-function */
import { RequestLike } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { Oauth2Error } from "../../errors";
import { parseAccessTokenRequest } from "../parse-token-request";
import {
  authorizationCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from "../z-grant-type";

describe("parseAccessTokenRequest", () => {
  describe("Authorization Code Grant", () => {
    it("should parse valid authorization code grant request", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant.grantType).toBe(authorizationCodeGrantIdentifier);
      expect(result.grant).toHaveProperty("code", "authorization-code-123");
      expect(result.pkceCodeVerifier).toBe("pkce-code-verifier");
      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeUndefined();
    });

    it("should parse authorization code grant request with PKCE code_verifier", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier-xyz",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant.grantType).toBe(authorizationCodeGrantIdentifier);
      expect(result.grant).toHaveProperty("code", "authorization-code-123");
      expect(result.pkceCodeVerifier).toBe("pkce-code-verifier-xyz");
    });

    it("should throw error when code parameter is missing for authorization_code grant", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should parse authorization code grant request with DPoP header", () => {
      const headers = new Headers();
      headers.set(
        "DPoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwt).toBe(headers.get("DPoP"));
    });

    it("should parse authorization code grant request with client attestation", () => {
      const headers = new Headers();
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationJwt).toBe(
        headers.get("OAuth-Client-Attestation"),
      );
      expect(result.clientAttestation?.clientAttestationPopJwt).toBe(
        headers.get("OAuth-Client-Attestation-PoP"),
      );
    });
  });

  describe("Refresh Token Grant", () => {
    it("should parse valid refresh token grant request", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "refresh_token",
        refresh_token: "refresh-token-xyz",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant.grantType).toBe(refreshTokenGrantIdentifier);
      expect(result.grant).toHaveProperty("refreshToken", "refresh-token-xyz");
      expect(result.pkceCodeVerifier).toBeUndefined();
      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeUndefined();
    });

    it("should throw error when refresh_token parameter is missing for refresh_token grant", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "refresh_token",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should parse refresh token grant request with DPoP header", () => {
      const headers = new Headers();
      headers.set(
        "DPoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "refresh_token",
        refresh_token: "refresh-token-xyz",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwt).toBe(headers.get("DPoP"));
    });

    it("should parse refresh token grant request with client attestation", () => {
      const headers = new Headers();
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "refresh_token",
        refresh_token: "refresh-token-xyz",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationJwt).toBe(
        headers.get("OAuth-Client-Attestation"),
      );
      expect(result.clientAttestation?.clientAttestationPopJwt).toBe(
        headers.get("OAuth-Client-Attestation-PoP"),
      );
    });
  });

  describe("Grant Type Validation", () => {
    it("should throw error for unsupported grant type", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "password",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should throw error when grant_type is missing", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });
  });

  describe("DPoP Header Validation", () => {
    it("should throw error for invalid DPoP header", () => {
      const headers = new Headers();
      headers.set("DPoP", "invalid-dpop-jwt");

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("not a valid JWT format");
    });

    it("should throw error for malformed DPoP JWT (missing parts)", () => {
      const headers = new Headers();
      headers.set("DPoP", "header.payload");

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });

    it("should return undefined dpop when DPoP header is not present", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeUndefined();
    });
  });

  describe("Client Attestation Header Validation", () => {
    it("should throw error for invalid client attestation header", () => {
      const headers = new Headers();
      headers.set("OAuth-Client-Attestation", "invalid-jwt");
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("not in valid JWT format");
    });

    it("should throw error when client attestation header is present without PoP header", () => {
      const headers = new Headers();
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });

    it("should return undefined client attestation when headers are not present", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.clientAttestation).toBeUndefined();
    });
  });

  describe("Combined Scenarios", () => {
    it("should parse request with both DPoP and client attestation headers", () => {
      const headers = new Headers();
      headers.set(
        "DPoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwt).toBe(headers.get("DPoP"));
      expect(result.clientAttestation).toBeDefined();
      expect(result.clientAttestation?.clientAttestationJwt).toBe(
        headers.get("OAuth-Client-Attestation"),
      );
      expect(result.clientAttestation?.clientAttestationPopJwt).toBe(
        headers.get("OAuth-Client-Attestation-PoP"),
      );
      expect(result.pkceCodeVerifier).toBe("pkce-verifier");
    });

    it("should parse request with neither DPoP nor client attestation", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeUndefined();
      expect(result.clientAttestation).toBeUndefined();
    });

    it("should handle case-insensitive header names", () => {
      const headers = new Headers();
      headers.set(
        "dpop",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );
      headers.set(
        "oauth-client-attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "oauth-client-attestation-pop",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });

    it("should parse refresh token grant with all optional security headers", () => {
      const headers = new Headers();
      headers.set(
        "DPoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );
      headers.set(
        "OAuth-Client-Attestation",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature",
      );
      headers.set(
        "OAuth-Client-Attestation-PoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        client_id: "test-client-id",
        grant_type: "refresh_token",
        refresh_token: "refresh-token-xyz",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.grant.grantType).toBe(refreshTokenGrantIdentifier);
      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });

  describe("Request Body Validation", () => {
    it("should throw error for completely invalid request body", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        invalid_field: "some-value",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          request: mockRequest,
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should accept additional fields due to passthrough", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com/token",
      };

      const accessTokenRequest = {
        additional_field: "some-value",
        client_id: "test-client-id",
        code: "authorization-code-123",
        code_verifier: "pkce-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        request: mockRequest,
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.accessTokenRequest).toHaveProperty(
        "additional_field",
        "some-value",
      );
    });
  });
});
