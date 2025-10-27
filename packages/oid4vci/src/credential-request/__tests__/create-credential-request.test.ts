import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vciError } from "../../errors";
import {
  CredentialRequestOptions,
  createCredentialRequest,
} from "../create-credential-request";

const mockCallbacks = {
  signJwt: vi.fn(),
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

describe("createCredentialRequest", () => {
  const baseOptions: CredentialRequestOptions = {
    callbacks: mockCallbacks,
    clientId: "test-client-id",
    credential_identifier: "test-credential-identifier",
    issuerIdentifier: "https://issuer.example.com",
    nonce: "test-nonce-123",
    signer: mockSigner,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockCallbacks.signJwt.mockResolvedValue({
      jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test-signature",
    });
  });

  it("should successfully create a credential request", async () => {
    const result = await createCredentialRequest(baseOptions);

    expect(result).toEqual({
      credential_identifier: "test-credential-identifier",
      proof: {
        jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test-signature",
        proof_type: "jwt",
      },
    });
  });

  it("should call signJwt with correct parameters", async () => {
    await createCredentialRequest(baseOptions);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        jwk: mockSigner.publicJwk,
        typ: "openid4vci-proof+jwt",
      },
      payload: {
        aud: "https://issuer.example.com",
        iat: expect.any(Number),
        iss: "test-client-id",
        nonce: "test-nonce-123",
      },
    });
  });

  it("should include current timestamp in the proof JWT payload", async () => {
    const beforeTimestamp = Math.floor(Date.now() / 1000);
    await createCredentialRequest(baseOptions);
    const afterTimestamp = Math.floor(Date.now() / 1000);

    const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
    expect(signJwtCall).toBeDefined();
    if (!signJwtCall) throw new Error("signJwtCall is undefined");
    const iat = signJwtCall[1].payload.iat;

    expect(iat).toBeGreaterThanOrEqual(beforeTimestamp);
    expect(iat).toBeLessThanOrEqual(afterTimestamp);
  });

  it("should use the provided credential_identifier in the request", async () => {
    const customOptions = {
      ...baseOptions,
      credential_identifier: "custom-credential-id",
    };

    const result = await createCredentialRequest(customOptions);

    expect(result.credential_identifier).toBe("custom-credential-id");
  });

  it("should throw Oid4vciError when signJwt callback fails", async () => {
    mockCallbacks.signJwt.mockRejectedValue(new Error("Signing failed"));

    await expect(createCredentialRequest(baseOptions)).rejects.toThrow(
      Oid4vciError,
    );
    await expect(createCredentialRequest(baseOptions)).rejects.toThrow(
      "Unexpected error during create credential request: Signing failed",
    );
  });

  it("should include proof_type as jwt in the credential request", async () => {
    const result = await createCredentialRequest(baseOptions);

    expect(result.proof.proof_type).toBe("jwt");
  });

  it("should use different nonce values correctly", async () => {
    const customNonce = "custom-nonce-value";
    const customOptions = {
      ...baseOptions,
      nonce: customNonce,
    };

    await createCredentialRequest(customOptions);

    const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
    expect(signJwtCall).toBeDefined();
    if (!signJwtCall) throw new Error("signJwtCall is undefined");
    expect(signJwtCall[1].payload.nonce).toBe(customNonce);
  });

  it("should use the issuerIdentifier as audience in proof JWT", async () => {
    const customIssuer = "https://custom-issuer.example.org";
    const customOptions = {
      ...baseOptions,
      issuerIdentifier: customIssuer,
    };

    await createCredentialRequest(customOptions);

    const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
    expect(signJwtCall).toBeDefined();
    if (!signJwtCall) throw new Error("signJwtCall is undefined");
    expect(signJwtCall[1].payload.aud).toBe(customIssuer);
  });

  it("should use the clientId as issuer in proof JWT", async () => {
    const customClientId = "custom-client-id";
    const customOptions = {
      ...baseOptions,
      clientId: customClientId,
    };

    await createCredentialRequest(customOptions);

    const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
    expect(signJwtCall).toBeDefined();
    if (!signJwtCall) throw new Error("signJwtCall is undefined");
    expect(signJwtCall[1].payload.iss).toBe(customClientId);
  });
});
