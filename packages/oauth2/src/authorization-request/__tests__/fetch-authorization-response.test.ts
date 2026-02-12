import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchPushedAuthorizationResponse,
  fetchPushedAuthorizationResponseOptions,
} from "../fetch-authorization-response";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("fetchPushedAuthorizationResponse", () => {
  const baseOptions: fetchPushedAuthorizationResponseOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    clientAttestationDPoP: "test-client-attestation-dpop-jwt",
    pushedAuthorizationRequest: {
      client_id: "test-client-id",
      pkceCodeVerifier: "test-pkce-code-verifier",
      request: "test-jwt-request-token",
    },
    pushedAuthorizationRequestEndpoint: "https://auth-server.example.com/par",
    walletAttestation: "test-wallet-attestation-jwt",
  };

  beforeEach(() => {
    vi.restoreAllMocks();
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

      const result = await fetchPushedAuthorizationResponse(baseOptions);

      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth-server.example.com/par",
        {
          body: new URLSearchParams({
            client_id: "test-client-id",
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

      const result = await fetchPushedAuthorizationResponse(baseOptions);

      expect(result).toEqual({
        additional_property: "should-be-preserved",
        expires_in: 120,
        request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
      });
    });
  });

  describe("HTTP error handling", () => {
    it("should throw UnexpectedStatusCodeError for 400 status", async () => {
      const mockResponse = {
        headers: {
          get: vi.fn().mockReturnValue("text/plain"),
        },
        status: 400,
        text: vi.fn().mockResolvedValue("Bad Request: Invalid client_id"),
        url: "https://auth-server.example.com/par",
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(
        fetchPushedAuthorizationResponse(baseOptions),
      ).rejects.toThrow(UnexpectedStatusCodeError);

      await expect(
        fetchPushedAuthorizationResponse(baseOptions),
      ).rejects.toThrow(
        "message=Http request failed. Expected 201, got 400, url: https://auth-server.example.com/par reason=Bad Request: Invalid client_id statusCode=400",
      );

      const error = await fetchPushedAuthorizationResponse(baseOptions).catch(
        (e) => e,
      );
      expect(error.statusCode).toBe(400);
    });

    it("should throw UnexpectedStatusCodeError for 500 status", async () => {
      const mockResponse = {
        headers: {
          get: vi.fn().mockReturnValue("text/plain"),
        },
        status: 500,
        text: vi.fn().mockResolvedValue("Internal Server Error"),
        url: "https://auth-server.example.com/par",
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationResponse(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(UnexpectedStatusCodeError);
      expect(error.statusCode).toBe(500);
      expect(error.message).toContain(
        "message=Http request failed. Expected 201, got 500, url: https://auth-server.example.com/par reason=Internal Server Error statusCode=500",
      );
    });

    it("should throw for any non-201 status code", async () => {
      const statusCodes = [200, 202, 400, 401, 403, 404, 422, 500, 502, 503];

      for (const statusCode of statusCodes) {
        mockFetch.mockClear();
        const mockResponse = {
          headers: {
            get: vi.fn().mockReturnValue("text/plain"),
          },
          status: statusCode,
          text: vi.fn().mockResolvedValue(`Status ${statusCode} error`),
          url: "https://auth-server.example.com/par",
        };
        mockFetch.mockResolvedValue(mockResponse);

        const error = await fetchPushedAuthorizationResponse(baseOptions).catch(
          (e) => e,
        );

        expect(error).toBeInstanceOf(UnexpectedStatusCodeError);
        expect(error.statusCode).toBe(statusCode);
      }
    });
  });

  describe("response parsing errors", () => {
    it("should throw ValidationError for missing request_uri", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          expires_in: 60,
          // missing request_uri
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationResponse(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(ValidationError);
      expect(error.message).toContain(
        "Failed to parse pushed authorization response",
      );
    });

    it("should throw ValidationError for missing expires_in", async () => {
      const mockResponse = {
        json: vi.fn().mockResolvedValue({
          request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
          // missing expires_in
        }),
        status: 201,
      };
      mockFetch.mockResolvedValue(mockResponse);

      const error = await fetchPushedAuthorizationResponse(baseOptions).catch(
        (e) => e,
      );

      expect(error).toBeInstanceOf(ValidationError);
      expect(error.message).toContain(
        "Failed to parse pushed authorization response",
      );
    });
  });
});

describe("fetchPushedAuthorizationResponse - unsigned PAR", () => {
  const baseOptions: fetchPushedAuthorizationResponseOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    clientAttestationDPoP: "test-client-attestation-dpop-jwt",
    pushedAuthorizationRequest: {
      client_id: "test-client-id",
      pkceCodeVerifier: "test-pkce-code-verifier",
      request: "test-jwt-request-token",
    },
    pushedAuthorizationRequestEndpoint: "https://auth-server.example.com/par",
    walletAttestation: "test-wallet-attestation-jwt",
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should successfully fetch unsigned pushed authorization request", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        expires_in: 60,
        request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
      }),
      status: 201,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const unsignedOptions: fetchPushedAuthorizationResponseOptions = {
      ...baseOptions,
      pushedAuthorizationRequest: {
        authorizationRequest: {
          client_id: "test-client-id",
          code_challenge: "test-code-challenge",
          code_challenge_method: "S256",
          redirect_uri: "https://client.example.com/callback",
          response_mode: "form_post",
          response_type: "code",
          scope: "openid",
          state: "test-state",
        },
        client_id: "test-client-id",
        pkceCodeVerifier: "test-pkce-code-verifier",
      },
    };

    const result = await fetchPushedAuthorizationResponse(unsignedOptions);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://auth-server.example.com/par",
      {
        body: new URLSearchParams({
          client_id: "test-client-id",
          code_challenge: "test-code-challenge",
          code_challenge_method: "S256",
          redirect_uri: "https://client.example.com/callback",
          response_mode: "form_post",
          response_type: "code",
          scope: "openid",
          state: "test-state",
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

  it("should JSON-serialise authorization_details in unsigned request body", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        expires_in: 60,
        request_uri: "urn:ietf:params:oauth:request_uri:test-uri",
      }),
      status: 201,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const authDetails = [
      {
        credential_configuration_id: "test-config-1",
        type: "openid_credential" as const,
      },
      {
        credential_configuration_id: "test-config-2",
        type: "openid_credential" as const,
      },
    ];

    const unsignedOptions: fetchPushedAuthorizationResponseOptions = {
      ...baseOptions,
      pushedAuthorizationRequest: {
        authorizationRequest: {
          authorization_details: authDetails,
          client_id: "test-client-id",
          code_challenge: "test-code-challenge",
          code_challenge_method: "S256",
          redirect_uri: "https://client.example.com/callback",
          response_mode: "form_post",
          response_type: "code",
          state: "test-state",
        },
        client_id: "test-client-id",
        pkceCodeVerifier: "test-pkce-code-verifier",
      },
    };

    await fetchPushedAuthorizationResponse(unsignedOptions);

    const expectedParams = new URLSearchParams();
    expectedParams.append("authorization_details", JSON.stringify(authDetails));
    expectedParams.append("client_id", "test-client-id");
    expectedParams.append("code_challenge", "test-code-challenge");
    expectedParams.append("code_challenge_method", "S256");
    expectedParams.append(
      "redirect_uri",
      "https://client.example.com/callback",
    );
    expectedParams.append("response_mode", "form_post");
    expectedParams.append("response_type", "code");
    expectedParams.append("state", "test-state");

    expect(mockFetch).toHaveBeenCalledWith(
      "https://auth-server.example.com/par",
      {
        body: expectedParams,
        headers: {
          [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
          [HEADERS.OAUTH_CLIENT_ATTESTATION]: "test-wallet-attestation-jwt",
          [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]:
            "test-client-attestation-dpop-jwt",
        },
        method: "POST",
      },
    );
  });
});
