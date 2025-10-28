import { HashAlgorithm } from "@openid4vc/oauth2";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createTokenDPoP } from "..";

const mockCallbacks = {
  generateRandom: vi.fn(),
  hash: vi.fn(),
  signJwt: vi.fn(),
  verifyJwt: vi.fn(),
};

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  mockCallbacks.generateRandom.mockResolvedValue(new Uint8Array([1, 2, 3, 4]));
  mockCallbacks.signJwt.mockResolvedValue("test-dpop-jwt");
  mockCallbacks.hash.mockResolvedValue(new Uint8Array([5, 6, 7, 8]));
  mockCallbacks.verifyJwt.mockResolvedValue({ verified: true });
});

describe("createDpopJwt", () => {
  it("should create a DPoP JWT without access token", async () => {
    const result = await createTokenDPoP({
      callbacks: mockCallbacks,
      signer: mockSigner,
      tokenRequest: {
        method: "POST",
        url: "https://example.com/token",
      },
    });

    expect(result).toBe("test-dpop-jwt");
    expect(mockCallbacks.generateRandom).toHaveBeenCalledWith(32);
    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        jwk: mockSigner.publicJwk,
        typ: "dpop+jwt",
      },
      payload: expect.objectContaining({
        htm: "POST",
        htu: "https://example.com/token",
        iat: expect.any(Number),
        jti: expect.any(String),
      }),
    });
  });

  it("should create a DPoP JWT without access token and custom jti", async () => {
    const result = await createTokenDPoP({
      callbacks: mockCallbacks,
      jti: "custom-jti",
      signer: mockSigner,
      tokenRequest: {
        method: "POST",
        url: "https://example.com/token",
      },
    });

    expect(result).toBe("test-dpop-jwt");
    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        jwk: mockSigner.publicJwk,
        typ: "dpop+jwt",
      },
      payload: expect.objectContaining({
        htm: "POST",
        htu: "https://example.com/token",
        iat: expect.any(Number),
        jti: "custom-jti",
      }),
    });
  });

  it("should create a DPoP JWT with access token", async () => {
    const accessToken = "test-access-token";

    await createTokenDPoP({
      accessToken,
      callbacks: mockCallbacks,
      signer: mockSigner,
      tokenRequest: {
        method: "GET",
        url: "https://example.com/resource",
      },
    });

    expect(mockCallbacks.hash).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      HashAlgorithm.Sha256,
    );
    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        ath: expect.any(String),
        htm: "GET",
        htu: "https://example.com/resource",
      }),
    });
  });

  it("should strip query parameters and hash from URL", async () => {
    await createTokenDPoP({
      callbacks: mockCallbacks,
      signer: mockSigner,
      tokenRequest: {
        method: "POST",
        url: "https://example.com/token?param=value#fragment",
      },
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        htu: "https://example.com/token",
      }),
    });
  });

  it("should use provided issuedAt date", async () => {
    const issuedAt = new Date("2023-01-01T00:00:00Z");

    await createTokenDPoP({
      callbacks: mockCallbacks,
      issuedAt,
      signer: mockSigner,
      tokenRequest: {
        method: "POST",
        url: "https://example.com/token",
      },
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        iat: 1672531200,
      }),
    });
  });

  it("should throw a CreateTokenDPoP error in case neither a jti nor a generateRandomCallback are passed", async () => {
    const callbacksWithoutGenerateRandom = {
      hash: mockCallbacks.hash,
      signJwt: mockCallbacks.signJwt,
      verifyJwt: mockCallbacks.verifyJwt,
    };

    await expect(
      createTokenDPoP({
        callbacks: callbacksWithoutGenerateRandom,
        signer: mockSigner,
        tokenRequest: {
          method: "POST",
          url: "https://example.com/token",
        },
      }),
    ).rejects.toThrow(
      "Error: neither a default jti nor a generateRandom callback have been provided",
    );
  });
});
