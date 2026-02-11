import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
} from "@pagopa/io-wallet-utils";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MrtdPopError } from "../../errors";
import { fetchMrtdPopInit } from "../fetch-mrtd-pop-init";

const mockFetch = vi.fn();
const mockVerifyJwt = vi.fn();

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "server-key-1",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const h = Base64.encode(JSON.stringify(header), true);
  const p = Base64.encode(JSON.stringify(payload), true);
  return `${h}.${p}.test-signature`;
}

const validInitResponseHeader = {
  alg: "ES256",
  kid: "server-key-1",
  typ: "mrtd-ias-pop+jwt",
};

const validInitResponsePayload = {
  aud: "https://wallet.example.com",
  challenge: "challenge-abc-123",
  exp: Math.floor(Date.now() / 1000) + 3600,
  htm: "POST",
  htu: "https://pid-provider.example.com/edoc-proof/verify",
  iat: Math.floor(Date.now() / 1000),
  iss: "https://pid-provider.example.com",
  mrtd_pop_nonce: "nonce-xyz-789",
};

const baseOptions = {
  callbacks: {
    fetch: mockFetch,
    verifyJwt: mockVerifyJwt,
  },
  clientAttestationDPoP: "test-client-attestation-dpop",
  mrtdAuthSession: "session-123",
  mrtdPopJwtNonce: "nonce-456",
  popInitEndpoint: "https://pid-provider.example.com/edoc-proof/init",
  signer: mockSigner,
  walletAttestation: "test-wallet-attestation",
};

describe("fetchMrtdPopInit - successful requests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockVerifyJwt.mockResolvedValue({
      signerJwk: { kid: "server-key-1", kty: "EC" },
      verified: true,
    });
  });

  it("should fetch and parse the init response JWT", async () => {
    const responseJwt = makeJwt(
      validInitResponseHeader,
      validInitResponsePayload,
    );

    mockFetch.mockResolvedValue({
      status: 202,
      text: vi.fn().mockResolvedValue(responseJwt),
    });

    const result = await fetchMrtdPopInit(baseOptions);

    expect(result).toEqual({
      challenge: "challenge-abc-123",
      mrtdPopNonce: "nonce-xyz-789",
      mrz: undefined,
      popVerifyEndpoint: "https://pid-provider.example.com/edoc-proof/verify",
    });
  });

  it("should include mrz when present in response", async () => {
    const responseJwt = makeJwt(validInitResponseHeader, {
      ...validInitResponsePayload,
      mrz: "P<ITABIANCHI<<MARIO<<<",
    });

    mockFetch.mockResolvedValue({
      status: 202,
      text: vi.fn().mockResolvedValue(responseJwt),
    });

    const result = await fetchMrtdPopInit(baseOptions);

    expect(result.mrz).toBe("P<ITABIANCHI<<MARIO<<<");
  });

  it("should send correct headers and body", async () => {
    const responseJwt = makeJwt(
      validInitResponseHeader,
      validInitResponsePayload,
    );

    mockFetch.mockResolvedValue({
      status: 202,
      text: vi.fn().mockResolvedValue(responseJwt),
    });

    await fetchMrtdPopInit(baseOptions);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://pid-provider.example.com/edoc-proof/init",
      {
        body: JSON.stringify({
          mrtd_auth_session: "session-123",
          mrtd_pop_jwt_nonce: "nonce-456",
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

describe("fetchMrtdPopInit - error handling", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockVerifyJwt.mockResolvedValue({
      signerJwk: { kid: "server-key-1", kty: "EC" },
      verified: true,
    });
  });

  it("should throw UnexpectedStatusCodeError for non-202 status", async () => {
    mockFetch.mockResolvedValue({
      headers: {
        get: vi.fn().mockReturnValue("application/json"),
      },
      json: vi.fn().mockResolvedValue({ error: "invalid_request" }),
      status: 400,
      text: vi.fn().mockResolvedValue("Bad Request"),
      url: "https://pid-provider.example.com/edoc-proof/init",
    });

    await expect(fetchMrtdPopInit(baseOptions)).rejects.toThrow(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw MrtdPopError for network errors", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(fetchMrtdPopInit(baseOptions)).rejects.toThrow(MrtdPopError);
  });

  it("should throw when response JWT has invalid schema", async () => {
    const invalidJwt = makeJwt(
      { alg: "ES256", kid: "key-1", typ: "wrong-typ" },
      validInitResponsePayload,
    );

    mockFetch.mockResolvedValue({
      status: 202,
      text: vi.fn().mockResolvedValue(invalidJwt),
    });

    await expect(fetchMrtdPopInit(baseOptions)).rejects.toThrow();
  });
});
