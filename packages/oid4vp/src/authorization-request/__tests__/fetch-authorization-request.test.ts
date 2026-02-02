import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  AuthorizationRequestObject,
  Openid4vpAuthorizationRequestHeader,
} from "../z-request-object";

import { InvalidRequestUriMethodError, Oid4vpError } from "../../errors";
import { fetchAuthorizationRequest } from "../fetch-authorization-request";
import { parseAuthorizeRequest } from "../parse-authorization-request";

vi.mock("../parse-authorization-request");

describe("fetchAuthorizationRequest", () => {
  const mockFetch = vi.fn();
  const mockVerifyJwt = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
    verifyJwt: mockVerifyJwt,
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
    ).rejects.toThrow("Either request or request_uri parameter must be present");
  });

  it("should fetch request object using GET by default", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";
    const parsedRequestObject = { some: "data" };
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      trust_chain: ["mock-trust-chain"],
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: parsedRequestObject as unknown as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({ method: "GET" }),
    );
    expect(parseAuthorizeRequest).toHaveBeenCalledWith({
      callbacks: mockCallbacks,
      requestObjectJwt,
    });
    expect(result).toEqual({
      parsedAuthorizeRequest: {
        header: mockHeader,
        payload: parsedRequestObject,
      },
      parsedQrCode: {
        clientId: "123",
        requestUri: "https://request.com",
        requestUriMethod: "get",
      },
      sendBy: "reference",
    });
  });

  it("should fetch request object using POST if specified", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com&request_uri_method=post";
    const requestObjectJwt = "mock-jwt";
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
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

  it("should rethrow Oid4vpError from parseAuthorizeRequest", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    const error = new Oid4vpError("Parse error");
    vi.mocked(parseAuthorizeRequest).mockRejectedValue(error);

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(error);
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

  it("should handle authorizationRequestHeader in the result", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      trust_chain: ["mock-trust-chain"],
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: { some: "data" } as unknown as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
    });

    expect(result.parsedAuthorizeRequest.header).toEqual(mockHeader);
    expect(result.parsedAuthorizeRequest.header.kid).toBe("test-kid");
    expect(result.parsedAuthorizeRequest.header.trust_chain).toBeDefined();
  });
});

describe("fetchAuthorizationRequest - by value mode", () => {
  const mockFetch = vi.fn();
  const mockVerifyJwt = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
    verifyJwt: mockVerifyJwt,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle request parameter (by value)", async () => {
    const requestJwt = "eyJhbGciOiJFUzI1NiJ9...";
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=${requestJwt}`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("value");
    expect(result.parsedQrCode.clientId).toBe("test-client");
    expect(result.parsedQrCode.requestUri).toBeUndefined();
    expect(mockFetch).not.toHaveBeenCalled(); // No fetch for inline JWT
    expect(parseAuthorizeRequest).toHaveBeenCalledWith({
      callbacks: mockCallbacks,
      requestObjectJwt: requestJwt,
    });
  });

  it("should return sendBy='reference' for request_uri mode", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("reference");
    expect(mockFetch).toHaveBeenCalled();
  });

  it("should throw error when both request and request_uri are present", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=eyJhbGc...&request_uri=https://rp.example.org/request`;

    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: url,
        callbacks: mockCallbacks,
      }),
    ).rejects.toThrow(
      "request and request_uri cannot both be present",
    );
  });

  it("should properly parse long inline request JWT", async () => {
    // Test with realistic JWT length (QR codes can handle ~4KB)
    const longJwt =
      "eyJhbGciOiJFUzI1NiJ9." + "A".repeat(2000) + "." + "B".repeat(300);
    const url = `https://wallet.example.org/authorize?client_id=test-client&request=${longJwt}`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.sendBy).toBe("value");
    expect(parseAuthorizeRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        requestObjectJwt: longJwt,
      }),
    );
  });
});

describe("fetchAuthorizationRequest - POST with wallet metadata", () => {
  const mockFetch = vi.fn();
  const mockVerifyJwt = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
    verifyJwt: mockVerifyJwt,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should send wallet_metadata in POST body when provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;

    const walletMetadata = {
      authorization_endpoint: "https://wallet.example.org/authorize",
      response_types_supported: ["vp_token"],
      response_modes_supported: ["direct_post.jwt"],
      vp_formats_supported: {
        jwt_vc_json: { alg_values_supported: ["ES256"] },
      },
    };

    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      walletMetadata,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: expect.stringContaining("wallet_metadata="),
      }),
    );

    // Verify body contains JSON-encoded metadata
    const callArgs = mockFetch.mock.calls[0];
    const body = new URLSearchParams(callArgs[1].body);
    const decodedMetadata = JSON.parse(body.get("wallet_metadata")!);
    expect(decodedMetadata).toEqual(walletMetadata);
  });

  it("should send wallet_nonce in POST body when provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      walletNonce: "test-nonce-12345",
    });

    const callArgs = mockFetch.mock.calls[0];
    const body = new URLSearchParams(callArgs[1].body);
    expect(body.get("wallet_nonce")).toBe("test-nonce-12345");
  });

  it("should send POST with empty body when no metadata provided", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
      // No walletMetadata or walletNonce
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "", // Empty body
      }),
    );
  });

  it("should use GET method when request_uri_method is get", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=get`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
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
    expect(callArgs[1].body).toBeUndefined();
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
  const mockVerifyJwt = vi.fn();
  const mockCallbacks = {
    fetch: mockFetch,
    verifyJwt: mockVerifyJwt,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should maintain existing behavior for by-reference GET requests", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.parsedAuthorizeRequest).toBeDefined();
    expect(result.parsedQrCode.clientId).toBe("test-client");
    expect(result.sendBy).toBe("reference");
    expect(mockFetch).toHaveBeenCalledWith(
      "https://rp.example.org/request",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("should work without walletMetadata/walletNonce (backward compatible)", async () => {
    const url = `https://wallet.example.org/authorize?client_id=test-client&request_uri=https://rp.example.org/request&request_uri_method=post`;
    const mockHeader = {
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-authz-req+jwt",
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => "eyJhbGciOiJFUzI1NiJ9...",
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue({
      header: mockHeader as unknown as Openid4vpAuthorizationRequestHeader,
      payload: {} as AuthorizationRequestObject,
    });

    // Old code didn't provide walletMetadata/walletNonce
    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl: url,
      callbacks: mockCallbacks,
    });

    expect(result.parsedAuthorizeRequest).toBeDefined();
    expect(result.parsedQrCode.requestUriMethod).toBe("post");
  });
});
