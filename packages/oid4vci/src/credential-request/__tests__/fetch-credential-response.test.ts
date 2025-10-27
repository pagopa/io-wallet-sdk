import {
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FetchCredentialResponseError } from "../../errors";
import {
  FetchCredentialResponseOptions,
  fetchTokenResponse,
} from "../fetch-credential-response";
import { CredentialRequest } from "../z-credential";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("fetchTokenResponse", () => {
  const mockCredentialRequest: CredentialRequest = {
    credential_identifier: "test-credential-id",
    proof: {
      jwt: "test-proof-jwt",
      proof_type: "jwt",
    },
  };

  const baseOptions: FetchCredentialResponseOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    clientAttestationDPoP: "test-client-attestation-dpop-jwt",
    credentialEndpoint: "https://issuer.example.com/credential",
    credentialRequest: mockCredentialRequest,
    dPoP: "test-dpop-jwt",
    walletAttestation: "test-wallet-attestation-jwt",
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should successfully fetch and parse credential response", async () => {
    const credentialResponseData = {
      credentials: {
        credential: "test-credential-data",
      },
    };

    const mockResponse = {
      json: vi.fn(() => credentialResponseData),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchTokenResponse(baseOptions);

    expect(result).toEqual(credentialResponseData);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://issuer.example.com/credential",
      {
        body: JSON.stringify(mockCredentialRequest),
        headers: {
          "Content-Type": "application/json",
          DPoP: "test-dpop-jwt",
          "OAuth-Client-Attestation": "test-wallet-attestation-jwt",
          "OAuth-Client-Attestation-PoP": "test-client-attestation-dpop-jwt",
        },
        method: "POST",
      },
    );
  });

  it("should include all required headers in the request", async () => {
    const mockResponse = {
      json: vi.fn(() => ({
        credentials: { credential: "test-credential" },
      })),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await fetchTokenResponse(baseOptions);

    const fetchCall = mockFetch.mock.calls[0];
    expect(fetchCall).toBeDefined();
    if (!fetchCall) throw new Error("fetchCall is undefined");
    const headers = fetchCall[1].headers;

    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers.DPoP).toBe("test-dpop-jwt");
    expect(headers["OAuth-Client-Attestation"]).toBe(
      "test-wallet-attestation-jwt",
    );
    expect(headers["OAuth-Client-Attestation-PoP"]).toBe(
      "test-client-attestation-dpop-jwt",
    );
  });

  it("should send credential request as JSON in request body", async () => {
    const mockResponse = {
      json: vi.fn(() => ({
        credentials: { credential: "test-credential" },
      })),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await fetchTokenResponse(baseOptions);

    const fetchCall = mockFetch.mock.calls[0];
    expect(fetchCall).toBeDefined();
    if (!fetchCall) throw new Error("fetchCall is undefined");
    const body = fetchCall[1].body;

    expect(body).toBe(JSON.stringify(mockCredentialRequest));
  });

  it("should use POST method for the request", async () => {
    const mockResponse = {
      json: vi.fn(() => ({
        credentials: { credential: "test-credential" },
      })),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await fetchTokenResponse(baseOptions);

    const fetchCall = mockFetch.mock.calls[0];
    expect(fetchCall).toBeDefined();
    if (!fetchCall) throw new Error("fetchCall is undefined");
    expect(fetchCall[1].method).toBe("POST");
  });

  it("should throw UnexpectedStatusCodeError when response status is not 200", async () => {
    const mockResponse = {
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: () => Promise.resolve({ error: "Bad Request" }),
      status: 400,
      text: () => Promise.resolve(JSON.stringify({ error: "Bad Request" })),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw ValidationError when response has invalid structure", async () => {
    const mockResponse = {
      json: vi.fn(() => ({ invalid: "data" })),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should throw FetchCredentialResponseError when a network error occurs", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      FetchCredentialResponseError,
    );
    await expect(fetchTokenResponse(baseOptions)).rejects.toThrow(
      "Unexpected error during credential response: Network error",
    );
  });

  it("should call credential endpoint with correct URL", async () => {
    const customEndpoint = "https://custom-issuer.example.org/cred";
    const mockResponse = {
      json: vi.fn(() => ({
        credentials: { credential: "test-credential" },
      })),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await fetchTokenResponse({
      ...baseOptions,
      credentialEndpoint: customEndpoint,
    });

    expect(mockFetch).toHaveBeenCalledWith(customEndpoint, expect.any(Object));
  });

  it("should handle deferred credential response with transaction_id", async () => {
    const deferredResponse = {
      lead_time: 300,
      transaction_id: "test-transaction-id",
    };

    const mockResponse = {
      json: vi.fn(() => deferredResponse),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchTokenResponse(baseOptions);

    expect(result).toEqual(deferredResponse);
    expect(result.transaction_id).toBe("test-transaction-id");
    expect(result.lead_time).toBe(300);
  });
});
