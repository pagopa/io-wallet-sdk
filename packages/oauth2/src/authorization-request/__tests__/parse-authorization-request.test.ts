/* eslint-disable max-lines-per-function */
import { RequestLike } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { Oauth2Error } from "../../errors";
import { parseAuthorizationRequest } from "../parse-authorization-request";

describe("parseAuthorizationRequest", () => {
  describe("DPoP parsing", () => {
    it("should parse authorization request with DPoP header", () => {
      const headers = new Headers();
      headers.set(
        "DPoP",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature",
      );

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.dpop?.jwt).toBe(headers.get("DPoP"));
    });

    it("should return undefined dpop when DPoP header is not present", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
        request: mockRequest,
      });

      expect(result.dpop).toBeUndefined();
    });

    it("should throw error for invalid DPoP header", () => {
      const headers = new Headers();
      headers.set("DPoP", "invalid-dpop-jwt");

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com",
      };

      expect(() =>
        parseAuthorizationRequest({
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });

    it("should throw error for malformed DPoP JWT (missing parts)", () => {
      const headers = new Headers();
      headers.set("DPoP", "header.payload");

      const mockRequest: RequestLike = {
        headers,
        method: "POST",
        url: "https://issuer.example.com",
      };

      expect(() =>
        parseAuthorizationRequest({
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });
  });

  describe("Client Attestation parsing", () => {
    it("should parse authorization request with client attestation headers", () => {
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
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
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

    it("should return undefined client attestation when headers are not present", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
        request: mockRequest,
      });

      expect(result.clientAttestation).toBeUndefined();
    });

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
        url: "https://issuer.example.com",
      };

      expect(() =>
        parseAuthorizationRequest({
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
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
        url: "https://issuer.example.com",
      };

      expect(() =>
        parseAuthorizationRequest({
          request: mockRequest,
        }),
      ).toThrow(Oauth2Error);
    });
  });

  describe("Combined scenarios", () => {
    it("should parse authorization request with both DPoP and client attestation", () => {
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
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
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
    });

    it("should parse authorization request with neither DPoP nor client attestation", () => {
      const mockRequest: RequestLike = {
        headers: new Headers(),
        method: "POST",
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
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
        url: "https://issuer.example.com",
      };

      const result = parseAuthorizationRequest({
        request: mockRequest,
      });

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });
});
