import { beforeEach, describe, expect, it, vi } from "vitest";

import { CONTENT_TYPES, HEADERS } from "../../constants";
import { Oauth2ParseError } from "../../error/Oauth2ParseError";
import {
  FetchPushedAuthorizationRequestOptions,
  PushedAuthorizationRequestError,
  fetchPushedAuthorizationRequest,
} from "../fetch-authorization-request";

describe("PushedAuthorizationRequestError", () => {
  it("should create error with message only", () => {
    const error = new PushedAuthorizationRequestError("Test error message");

    expect(error.message).toBe("Test error message");
    expect(error.name).toBe("PushedAuthorizationRequestError");
    expect(error.statusCode).toBeUndefined();
    expect(error).toBeInstanceOf(Error);
  });

  it("should create error with message and status code", () => {
    const error = new PushedAuthorizationRequestError(
      "Test error message",
      400,
    );

    expect(error.message).toBe("Test error message");
    expect(error.name).toBe("PushedAuthorizationRequestError");
    expect(error.statusCode).toBe(400);
    expect(error).toBeInstanceOf(Error);
  });
});

describe("fetchPushedAuthorizationRequest", () => {
  const mockFetch = vi.fn();

  const baseOptions: FetchPushedAuthorizationRequestOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    clientAttestationDPoP: "test-client-attestation-dpop-jwt",
    pushedAuthorizationRequestEndpoint: "https://auth-server.example.com/par",
    pushedAuthorizationRequestSigned: {
      client_id: "test-client-id",
      request: "test-jwt-request-token",
    },
    walletAttestation: "test-wallet-attestation-jwt",
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("successful requests", () => {
    it("should successfully fetch pushed authorization request", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          expires_in: 60,
          request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchPushedAuthorizationRequest(baseOptions);

      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth-server.example.com/par",
        {
          body: new URLSearchParams({
            clientId: "test-client-id",
            request: "test-jwt-request-token",
          }),
          headers: {
            [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
            [HEADERS.OAUTH_CLIENT_ATTESTATION]: "test-wallet-attestation-jwt",
            [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]:
              "test-client-attestation-dpop-jwt",
          },
          method: "POST",
        },
      );

      expect(result).toEqual({
        expires_in: 60,
        request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
      });
    });

    it("should handle response with additional properties", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          additional_property: "should-be-preserved",
          expires_in: 120,
          request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchPushedAuthorizationRequest(baseOptions);

      expect(result).toEqual({
        additional_property: "should-be-preserved",
        expires_in: 120,
        request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
      });
    });
  });

  describe("HTTP error handling", () => {
    it("should throw PushedAuthorizationRequestError for 400 status", async () => {
      const mockResponse = {
        status: 400,
        text: vi.fn().mockResolvedValue("Bad Request: Invalid client_id"),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(
        fetchPushedAuthorizationRequest(baseOptions),
      ).rejects.toThrow(PushedAuthorizationRequestError);

      await expect(
        fetchPushedAuthorizationRequest(baseOptions),
      ).rejects.toThrow(
        "Pushed authorization request failed with status 400. Expected 201 Created. Response: Bad Request: Invalid client_id",
      );

      const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
        (e) => e,
      );
      expect(error.statusCode).toBe(400);
    });

    it("should throw PushedAuthorizationRequestError for 500 status", async () => {
      const mockResponse = {
        status: 500,
        text: vi.fn().mockResolvedValue("Internal Server Error"),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(PushedAuthorizationRequestError);
      expect(error.statusCode).toBe(500);
      expect(error.message).toContain(
        "Pushed authorization request failed with status 500",
      );
    });

    it("should handle error response text extraction failure", async () => {
      const mockResponse = {
        status: 404,
        text: vi.fn().mockRejectedValue(new Error("Failed to read response")),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(PushedAuthorizationRequestError);
      expect(error.message).toContain("Unknown error");
      expect(error.statusCode).toBe(404);
    });

    it("should throw for any non-201 status code", async () => {
      const statusCodes = [200, 202, 400, 401, 403, 404, 422, 500, 502, 503];

      for (const statusCode of statusCodes) {
        mockFetch.mockClear();
        const mockResponse = {
          status: statusCode,
          text: vi.fn().mockResolvedValue(`Status ${statusCode} error`),
        };
        mockFetch.mockResolvedValue(mockResponse);

        const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
          (e) => e,
        );

        expect(error).toBeInstanceOf(PushedAuthorizationRequestError);
        expect(error.statusCode).toBe(statusCode);
      }
    });
  });

  describe("response parsing errors", () => {
    it("should throw Oauth2ParseError for missing request_uri", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          expires_in: 60,
          // missing request_uri
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(Oauth2ParseError);
      expect(error.message).toContain(
        "Failed to parse pushed authorization response",
      );
    });

    it("should throw Oauth2ParseError for missing expires_in", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
          // missing expires_in
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationRequest(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(Oauth2ParseError);
      expect(error.message).toContain(
        "Failed to parse pushed authorization response",
      );
    });
  });
});
