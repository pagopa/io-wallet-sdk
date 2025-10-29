import {
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchAuthorizationResponse } from "../fetch-authorization-response";

const mockFetch = vi.fn();

const MOCK_REDIRECT_URI = "https://redirect-uri.org";
const MOCK_RESPONSE_URI = "https://response-uri.org";
const MOCK_JARM = "MOCK_JARM";

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("fetchAuthorizationResponseTests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should send the authorization response and obtain the response_uri", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({
        redirect_uri: MOCK_REDIRECT_URI,
      }),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await fetchAuthorizationResponse({
      authorizationResponseJarm: MOCK_JARM,
      callbacks: {
        fetch: mockFetch,
      },
      presentationResponseUri: MOCK_RESPONSE_URI,
    });

    expect(result).toEqual({
      redirect_uri: MOCK_REDIRECT_URI,
    });
  });

  it("should throw an UnexpectedStatusCodeError in case of an unexpected status code", async () => {
    const mockResponse = {
      headers: new Headers(),
      status: 400,
      text: vi.fn().mockResolvedValue("Error"),
      url: "example.com",
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(
      fetchAuthorizationResponse({
        authorizationResponseJarm: MOCK_JARM,
        callbacks: {
          fetch: mockFetch,
        },
        presentationResponseUri: MOCK_RESPONSE_URI,
      }),
    ).rejects.toThrow(UnexpectedStatusCodeError);
  });

  it("should throw FetchAuthorizationResponseError in case the response json is malformed", async () => {
    const mockResponse = {
      json: vi.fn().mockRejectedValue("Mock JSON parsing error"),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(
      fetchAuthorizationResponse({
        authorizationResponseJarm: MOCK_JARM,
        callbacks: {
          fetch: mockFetch,
        },
        presentationResponseUri: MOCK_RESPONSE_URI,
      }),
    ).rejects.toThrow(/Mock JSON parsing error/);
  });

  it("should throw ValidationError in case the response json is missing the redirect_uri field", async () => {
    const mockResponse = {
      json: vi.fn().mockResolvedValue({}),
      status: 200,
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(
      fetchAuthorizationResponse({
        authorizationResponseJarm: MOCK_JARM,
        callbacks: {
          fetch: mockFetch,
        },
        presentationResponseUri: MOCK_RESPONSE_URI,
      }),
    ).rejects.toThrow(ValidationError);
  });
});
