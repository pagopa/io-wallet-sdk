import { beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidRequestUriMethodError, Oid4vpError } from "../../errors";
import { fetchAuthorizationRequest } from "../fetch-authorization-request";

describe("fetchAuthorizationRequest", () => {
  const mockFetch = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should throw error if client_id is missing", async () => {
    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl:
          "https://example.com?request_uri=https://request.com",
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should throw error if neither request nor request_uri is present", async () => {
    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: "https://example.com?client_id=client-123",
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(Oid4vpError);
    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: "https://example.com?client_id=client-123",
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(
      "Either request or request_uri parameter must be present",
    );
  });

  it("should fetch request object using GET by default", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({ method: "GET" }),
    );
    expect(result).toEqual({
      parsedQrCode: {
        clientId: "123",
        requestUri: "https://request.com",
        requestUriMethod: "get",
      },
      requestObjectJwt,
      sendBy: "reference",
    });
  });

  it("should fetch request object using POST if specified", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com&request_uri_method=post";
    const requestObjectJwt = "mock-jwt";

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      }),
    );
  });

  it("should throw error if fetch fails", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";

    mockFetch.mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    });

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should rethrow Oid4vpError on fetch failure", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";

    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    });

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should wrap unexpected errors in Oid4vpError", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";

    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should return request object JWT in the result", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(result.requestObjectJwt).toBe(requestObjectJwt);
    expect(result.sendBy).toBe("reference");
    expect(result.parsedQrCode.clientId).toBe("123");
  });
});

describe("fetchAuthorizationRequest - by value mode", () => {
  const mockFetch = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle request parameter (by value)", async () => {
    const requestJwt = "eyJhbGciOiJFUzI1NiJ9...";
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=${requestJwt}`;

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("value");
    expect(result.parsedQrCode.clientId).toBe("test-client");
    expect(result.parsedQrCode.requestUri).toBeUndefined();
    expect(result.requestObjectJwt).toBe(requestJwt);
    expect(mockFetch).not.toHaveBeenCalled(); // No fetch for inline JWT
  });

  it("should return sendBy='reference' for request_uri mode", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("reference");
    expect(result.requestObjectJwt).toBe(requestObjectJwt);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("should throw error when both request and request_uri are present", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=eyJhbGc...&request_uri=https://rp.example.org/request`;

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: url,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow("request and request_uri cannot both be present");
  });

  it("should properly handle long inline request JWT", async () => {
    // Test with realistic JWT length (QR codes can handle ~4KB)
    const longJwt =
      "eyJhbGciOiJFUzI1NiJ9." + "A".repeat(2000) + "." + "B".repeat(300);
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=${longJwt}`;

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("value");
    expect(result.requestObjectJwt).toBe(longJwt);
  });
});

describe("fetchAuthorizationRequest - POST with wallet metadata", () => {
  const mockFetch = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should send wallet_metadata in POST body when provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;

    const walletMetadata = {
      authorization_endpoint: "https://wallet.example.org/authorize",
      response_modes_supported: ["direct_post.jwt"],
      response_types_supported: ["vp_token"],
      vp_formats_supported: {
        jwt_vc_json: { alg_values_supported: ["ES256"] },
      },
    };

    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      walletMetadata,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({
        body: expect.stringContaining("wallet_metadata="),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      }),
    );

    // Verify body contains JSON-encoded metadata
    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs).toBeDefined();
    const body = new URLSearchParams(callArgs?.[1].body as string);
    const metadataValue = body.get("wallet_metadata");
    expect(metadataValue).toBeTruthy();
    const decodedMetadata = JSON.parse(metadataValue as string);
    expect(decodedMetadata).toEqual(walletMetadata);
  });

  it("should send wallet_nonce in POST body when provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      walletNonce: "test-nonce-12345",
    });

    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs).toBeDefined();
    const body = new URLSearchParams(callArgs?.[1].body as string);
    expect(body.get("wallet_nonce")).toBe("test-nonce-12345");
  });

  it("should send POST with empty body when no metadata provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      // No walletMetadata or walletNonce
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({
        body: "", // Empty body
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      }),
    );
  });

  it("should use GET method when request_uri_method is get", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=get`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      walletMetadata: {
        /* metadata should be ignored for GET */
        authorization_endpoint: "https://wallet.example.org/authorize",
      },
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({
        method: "GET",
      }),
    );

    // Verify no body sent with GET
    const callArgs = mockFetch.mock.calls[0];
    expect(callArgs).toBeDefined();
    expect(callArgs?.[1].body).toBeUndefined();
  });

  it("should throw InvalidRequestUriMethodError for invalid method", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=PUT`;

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: url,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(InvalidRequestUriMethodError);
  });
});

describe("fetchAuthorizationRequest - backward compatibility", () => {
  const mockFetch = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should maintain existing behavior for by-reference GET requests", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.requestObjectJwt).toBe(requestObjectJwt);
    expect(result.parsedQrCode.clientId).toBe("test-client");
    expect(result.sendBy).toBe("reference");
    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("should work without walletMetadata/walletNonce (backward compatible)", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const requestObjectJwt = "eyJhbGciOiJFUzI1NiJ9...";

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => requestObjectJwt,
    });

    // Old code didn't provide walletMetadata/walletNonce
    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.requestObjectJwt).toBe(requestObjectJwt);
    expect(result.parsedQrCode.requestUriMethod).toBe("post");
  });
});
