import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MrtdPopError } from "../../errors";
import { fetchMrtdPopVerify } from "../fetch-mrtd-pop-verify";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

const baseOptions = {
  callbacks: { fetch: mockFetch },
  clientAttestationDPoP: "test-client-attestation-dpop",
  mrtdAuthSession: "session-123",
  mrtdPopNonce: "nonce-xyz",
  mrtdValidationJwt: "signed-validation-jwt",
  popVerifyEndpoint: "https://pid-provider.example.com/edoc-proof/verify",
  walletAttestation: "test-wallet-attestation",
};

describe("fetchMrtdPopVerify - successful requests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should fetch and parse the verify response", async () => {
    mockFetch.mockResolvedValue({
      json: vi.fn().mockResolvedValue({
        mrtd_val_pop_nonce: "final-nonce-123",
        redirect_uri: "https://pid-provider.example.com/callback",
        status: "require_interaction",
        type: "redirect_to_web",
      }),
      status: 202,
    });

    const result = await fetchMrtdPopVerify(baseOptions);

    expect(result).toEqual({
      mrtdValPopNonce: "final-nonce-123",
      redirectUri: "https://pid-provider.example.com/callback",
    });
  });

  it("should send correct headers and body", async () => {
    mockFetch.mockResolvedValue({
      json: vi.fn().mockResolvedValue({
        mrtd_val_pop_nonce: "final-nonce-123",
        redirect_uri: "https://pid-provider.example.com/callback",
        status: "require_interaction",
        type: "redirect_to_web",
      }),
      status: 202,
    });

    await fetchMrtdPopVerify(baseOptions);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://pid-provider.example.com/edoc-proof/verify",
      {
        body: JSON.stringify({
          mrtd_auth_session: "session-123",
          mrtd_pop_nonce: "nonce-xyz",
          mrtd_validation_jwt: "signed-validation-jwt",
        }),
        headers: {
          [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.JSON,
          [HEADERS.OAUTH_CLIENT_ATTESTATION]: "test-wallet-attestation",
          [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]:
            "test-client-attestation-dpop",
        },
        method: "POST",
      },
    );
  });
});

describe("fetchMrtdPopVerify - error handling", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should throw UnexpectedStatusCodeError for non-202 status", async () => {
    mockFetch.mockResolvedValue({
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: vi.fn().mockResolvedValue({ error: "invalid_request" }),
      status: 400,
      text: vi.fn().mockResolvedValue("Bad Request"),
      url: "https://pid-provider.example.com/edoc-proof/verify",
    });

    await expect(fetchMrtdPopVerify(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw ValidationError for invalid response body", async () => {
    mockFetch.mockResolvedValue({
      json: vi.fn().mockResolvedValue({
        invalid: "response",
      }),
      status: 202,
    });

    await expect(fetchMrtdPopVerify(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should throw MrtdPopError for network errors", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(fetchMrtdPopVerify(baseOptions)).rejects.toThrow(MrtdPopError);
  });

  it("should throw ValidationError when redirect_uri is not a valid URL", async () => {
    mockFetch.mockResolvedValue({
      json: vi.fn().mockResolvedValue({
        mrtd_val_pop_nonce: "final-nonce-123",
        redirect_uri: "not-a-url",
        status: "require_interaction",
        type: "redirect_to_web",
      }),
      status: 202,
    });

    await expect(fetchMrtdPopVerify(baseOptions)).rejects.toThrow(
      ValidationError,
    );
  });
});
