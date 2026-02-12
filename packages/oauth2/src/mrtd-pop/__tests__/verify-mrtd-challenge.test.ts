import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { verifyMrtdChallenge } from "../verify-mrtd-challenge";

function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const h = Base64.encode(JSON.stringify(header), true);
  const p = Base64.encode(JSON.stringify(payload), true);
  return `${h}.${p}.test-signature`;
}

const validHeader = {
  alg: "ES256",
  kid: "key-1",
  typ: "mrtd-ias+jwt",
};

const validPayload = {
  aud: "https://wallet.example.com",
  exp: Math.floor(Date.now() / 1000) + 3600,
  htm: "POST",
  htu: "https://pid-provider.example.com/edoc-proof/init",
  iat: Math.floor(Date.now() / 1000),
  iss: "https://pid-provider.example.com",
  mrtd_auth_session: "session-123",
  mrtd_pop_jwt_nonce: "nonce-456",
  state: "state-789",
  status: "require_interaction",
  type: "mrtd+ias",
};

const mockVerifyJwt = vi.fn();

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "key-1",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

describe("verifyMrtdChallenge", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockVerifyJwt.mockResolvedValue({
      signerJwk: { kid: "key-1", kty: "EC" },
      verified: true,
    });
  });

  it("should verify a valid challenge JWT", async () => {
    const jwt = makeJwt(validHeader, validPayload);

    const result = await verifyMrtdChallenge({
      callbacks: { verifyJwt: mockVerifyJwt },
      challengeJwt: jwt,
      clientId: "https://wallet.example.com",
      signer: mockSigner,
    });

    expect(result.header).toEqual(expect.objectContaining(validHeader));
    expect(result.payload).toEqual(expect.objectContaining(validPayload));
    expect(mockVerifyJwt).toHaveBeenCalledTimes(1);
  });

  it("should throw when verifyJwt callback rejects", async () => {
    mockVerifyJwt.mockRejectedValue(new Error("Signature invalid"));
    const jwt = makeJwt(validHeader, validPayload);

    await expect(
      verifyMrtdChallenge({
        callbacks: { verifyJwt: mockVerifyJwt },
        challengeJwt: jwt,
        clientId: "https://wallet.example.com",
        signer: mockSigner,
      }),
    ).rejects.toThrow();
  });

  it("should throw when aud does not match clientId", async () => {
    const jwt = makeJwt(validHeader, validPayload);

    await expect(
      verifyMrtdChallenge({
        callbacks: { verifyJwt: mockVerifyJwt },
        challengeJwt: jwt,
        clientId: "https://wrong-client.example.com",
        signer: mockSigner,
      }),
    ).rejects.toThrow("aud claim does not match client_id");
  });

  it("should throw when JWT is expired", async () => {
    mockVerifyJwt.mockRejectedValue(new Error("JWT expired"));
    const expiredPayload = {
      ...validPayload,
      exp: Math.floor(Date.now() / 1000) - 3600,
      iat: Math.floor(Date.now() / 1000) - 7200,
    };
    const jwt = makeJwt(validHeader, expiredPayload);

    await expect(
      verifyMrtdChallenge({
        callbacks: { verifyJwt: mockVerifyJwt },
        challengeJwt: jwt,
        clientId: "https://wallet.example.com",
        signer: mockSigner,
      }),
    ).rejects.toThrow();
  });

  it("should throw when JWT has invalid header schema", async () => {
    const jwt = makeJwt({ alg: "ES256", typ: "jwt" }, validPayload);

    await expect(
      verifyMrtdChallenge({
        callbacks: { verifyJwt: mockVerifyJwt },
        challengeJwt: jwt,
        clientId: "https://wallet.example.com",
        signer: mockSigner,
      }),
    ).rejects.toThrow();
  });

  it("should throw when JWT has invalid payload schema", async () => {
    const incompletePayload = { ...validPayload, mrtd_auth_session: undefined };
    const jwt = makeJwt(validHeader, incompletePayload);

    await expect(
      verifyMrtdChallenge({
        callbacks: { verifyJwt: mockVerifyJwt },
        challengeJwt: jwt,
        clientId: "https://wallet.example.com",
        signer: mockSigner,
      }),
    ).rejects.toThrow();
  });
});
