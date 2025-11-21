import type { RequestDpopOptions } from "@openid4vc/oauth2";

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthorizationRequestObject } from "../z-request-object";

import { Oid4vpError } from "../../errors";
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
  const mockDpop = {
    jwt: "mock-dpop-jwt",
  } as unknown as RequestDpopOptions;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should throw error if client_id is missing", async () => {
    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl:
          "https://example.com?request_uri=https://request.com",
        callbacks: mockCallbacks,
        dpop: mockDpop,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should throw error if request_uri is missing", async () => {
    await expect(
      fetchAuthorizationRequest({
        authorizeRequestUrl: "https://example.com?client_id=client-123",
        callbacks: mockCallbacks,
        dpop: mockDpop,
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("should fetch request object using GET by default", async () => {
    const authorizeRequestUrl =
      "https://example.com?client_id=123&request_uri=https://request.com";
    const requestObjectJwt = "mock-jwt";
    const parsedRequestObject = { some: "data" };

    mockFetch.mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(requestObjectJwt),
    });

    vi.mocked(parseAuthorizeRequest).mockResolvedValue(
      parsedRequestObject as unknown as AuthorizationRequestObject,
    );

    const result = await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
      dpop: mockDpop,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({ method: "GET" }),
    );
    expect(parseAuthorizeRequest).toHaveBeenCalledWith({
      callbacks: mockCallbacks,
      dpop: mockDpop,
      requestObjectJwt,
    });
    expect(result).toEqual({
      baseUri: "https://example.com",
      path: "/",
      requestObject: parsedRequestObject,
      searchParams: expect.any(URLSearchParams),
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

    vi.mocked(parseAuthorizeRequest).mockResolvedValue(
      {} as AuthorizationRequestObject,
    );

    await fetchAuthorizationRequest({
      authorizeRequestUrl,
      callbacks: mockCallbacks,
      dpop: mockDpop,
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://request.com",
      expect.objectContaining({ method: "POST" }),
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
        dpop: mockDpop,
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
        dpop: mockDpop,
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
        dpop: mockDpop,
      }),
    ).rejects.toThrow(Oid4vpError);
  });
});
