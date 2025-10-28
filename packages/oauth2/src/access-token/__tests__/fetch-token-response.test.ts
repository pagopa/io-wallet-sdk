import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { HEADERS as OAUTH_HEADERS } from "../../constants";
import { FetchTokenResponseError } from "../../errors";
import {
  FetchTokenResponseOptions,
  fetchTokenResponse,
  toURLSearchParams,
} from "../fetch-token-response";
import { AccessTokenRequest } from "../z-token";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

const baseOptions: FetchTokenResponseOptions = {
  accessTokenEndpoint: "https://auth-server.example.com/token",
  accessTokenRequest: {
    code: "test-authorization-code",
    code_verifier: "test-code-verifier",
    grant_type: "authorization_code",
    redirect_uri: "https://app.example.com/callback",
  },
  callbacks: {
    fetch: mockFetch,
  },
  clientAttestationDPoP: "test-client-attestation-dpop-jwt",
  walletAttestation: "test-wallet-attestation-jwt",
};

describe("fetchTokenResponse - successful requests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should successfully fetch access token response", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        access_token: "test-access-token",
        expires_in: 3600,
        token_type: "DPoP",
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchTokenResponse(baseOptions);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://auth-server.example.com/token",
      {
        body: new URLSearchParams({
          code: "test-authorization-code",
          code_verifier: "test-code-verifier",
          grant_type: "authorization_code",
          redirect_uri: "https://app.example.com/callback",
        }),
        headers: {
          [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
          [OAUTH_HEADERS.OAUTH_CLIENT_ATTESTATION]: "test-wallet-attestation-jwt",
          [OAUTH_HEADERS.OAUTH_CLIENT_ATTESTATION_POP]:
            "test-client-attestation-dpop-jwt",
        },
        method: "POST",
      },
    );

    expect(result).toEqual({
      access_token: "test-access-token",
      expires_in: 3600,
      token_type: "DPoP",
    });
  });

  it("should handle response with authorization_details", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        access_token: "test-access-token",
        authorization_details: [
          {
            credential_configuration_id: "credential-config-1",
            credential_identifiers: ["credential-id-1", "credential-id-2"],
            type: "openid_credential",
          },
        ],
        expires_in: 3600,
        token_type: "DPoP",
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchTokenResponse(baseOptions);

    expect(result).toEqual({
      access_token: "test-access-token",
      authorization_details: [
        {
          credential_configuration_id: "credential-config-1",
          credential_identifiers: ["credential-id-1", "credential-id-2"],
          type: "openid_credential",
        },
      ],
      expires_in: 3600,
      token_type: "DPoP",
    });
  });

  it("should handle response without optional fields", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        access_token: "test-access-token",
        token_type: "DPoP",
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchTokenResponse(baseOptions);

    expect(result).toEqual({
      access_token: "test-access-token",
      token_type: "DPoP",
    });
  });
});

describe("fetchTokenResponse - HTTP error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should throw UnexpectedStatusCodeError for 400 status", async () => {
    const mockResponse = {
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: vi.fn().mockResolvedValue({
        error: "invalid_request",
        error_description: "Invalid request parameters",
      }),
      status: 400,
      text: vi.fn().mockResolvedValue("Bad Request"),
      url: "https://auth-server.example.com/token",
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw UnexpectedStatusCodeError for 401 status", async () => {
    const mockResponse = {
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: vi.fn().mockResolvedValue({
        error: "invalid_client",
        error_description: "Client authentication failed",
      }),
      status: 401,
      text: vi.fn().mockResolvedValue("Unauthorized"),
      url: "https://auth-server.example.com/token",
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw UnexpectedStatusCodeError for 500 status", async () => {
    const mockResponse = {
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: vi.fn().mockResolvedValue({
        error: "server_error",
        error_description: "Internal server error",
      }),
      status: 500,
      text: vi.fn().mockResolvedValue("Internal Server Error"),
      url: "https://auth-server.example.com/token",
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });
});

describe("fetchTokenResponse - validation error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should throw ValidationError when access_token is missing", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        expires_in: 3600,
        token_type: "DPoP",
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should throw ValidationError when token_type is not DPoP", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        access_token: "test-access-token",
        expires_in: 3600,
        token_type: "Bearer",
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should throw ValidationError when response is not valid JSON", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue(null),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });
});

describe("fetchTokenResponse - unexpected error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should throw FetchTokenResponseError for network errors", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      FetchTokenResponseError,
    );
  });

  it("should throw FetchTokenResponseError for JSON parsing errors", async () => {
    const mockResponse = {
      json: vi.fn().mockRejectedValue(new Error("Invalid JSON")),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      FetchTokenResponseError,
    );
  });

  it("should include error message in FetchTokenResponseError", async () => {
    mockFetch.mockRejectedValue(new Error("Connection timeout"));

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      /Connection timeout/,
    );
  });
});

describe("toURLSearchParams", () => {
  it("should convert basic string fields to URLSearchParams", () => {
    const request: AccessTokenRequest = {
      code: "test-code",
      code_verifier: "test-verifier",
      grant_type: "authorization_code",
      redirect_uri: "https://example.com/callback",
    };

    const result = toURLSearchParams(request);

    expect(result.get("code")).toBe("test-code");
    expect(result.get("code_verifier")).toBe("test-verifier");
    expect(result.get("grant_type")).toBe("authorization_code");
    expect(result.get("redirect_uri")).toBe("https://example.com/callback");
  });

  it("should skip undefined fields", () => {
    const request: AccessTokenRequest = {
      code: "test-code",
      code_verifier: undefined,
      grant_type: "authorization_code",
      redirect_uri: "https://example.com/callback",
    };

    const result = toURLSearchParams(request);

    expect(result.get("code")).toBe("test-code");
    expect(result.get("code_verifier")).toBeNull();
    expect(result.get("grant_type")).toBe("authorization_code");
    expect(result.get("redirect_uri")).toBe("https://example.com/callback");
  });

  it("should stringify object fields", () => {
    const request = {
      code: "test-code",
      custom_object: { key: "value", nested: { data: "test" } },
      grant_type: "authorization_code" as const,
    };

    const result = toURLSearchParams(request);

    expect(result.get("custom_object")).toBe(
      JSON.stringify({ key: "value", nested: { data: "test" } }),
    );
  });

  it("should convert number fields to strings", () => {
    const request = {
      grant_type: "authorization_code" as const,
      numeric_field: 12345,
    };

    const result = toURLSearchParams(request);

    expect(result.get("numeric_field")).toBe("12345");
  });

  it("should convert boolean fields to strings", () => {
    const request = {
      boolean_field: true,
      grant_type: "authorization_code" as const,
    };

    const result = toURLSearchParams(request);

    expect(result.get("boolean_field")).toBe("true");
  });

  it("should handle empty object", () => {
    const request = {
      grant_type: "authorization_code" as const,
    };

    const result = toURLSearchParams(request);

    expect(result.toString()).toBe("grant_type=authorization_code");
  });

  it("should handle multiple undefined fields", () => {
    const request: AccessTokenRequest = {
      code: undefined,
      code_verifier: undefined,
      grant_type: "authorization_code",
      redirect_uri: undefined,
    };

    const result = toURLSearchParams(request);

    expect(result.toString()).toBe("grant_type=authorization_code");
  });
});
