import { ValidationError } from "@openid4vc/utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NonceRequestError } from "../../errors";
import { GetNonceOptions, getNonce } from "../get-nonce";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("getNonce", () => {
  const baseOptions: GetNonceOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    nonceUrl: "https://example.com/nonce",
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should successfully fetch and parse nonce response", async () => {
    const response = {
      c_nonce: "test-nonce-123",
    };

    const mockResponse = {
      json: vi.fn().mockResolvedValue(response),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await getNonce(baseOptions);

    expect(result).toEqual(response);
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/nonce", {
      method: "POST",
    });
  });

  it("should throw NonceRequestError when fetch fails with non-200 status", async () => {
    mockFetch.mockResolvedValue({
      json: vi.fn().mockResolvedValue({ error: "Bad Request" }),
      status: 400,
    });

    await expect(getNonce(baseOptions)).rejects.toThrow(NonceRequestError);
  });

  it("should throw ValidationError when response has invalid structure", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({ invalid: "data" }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(getNonce(baseOptions)).rejects.toThrow(ValidationError);
  });

  it("should throw NonceRequestError when a network error occurs", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(getNonce(baseOptions)).rejects.toThrow(NonceRequestError);
  });
});
