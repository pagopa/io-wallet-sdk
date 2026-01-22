import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vciError } from "../../../errors";
import {
  CredentialRequestOptionsV1_0,
  createCredentialRequest,
} from "../create-credential-request";

const mockCallbacks = {
  signJwt: vi.fn(),
};

const mockSigner = {
  alg: "ES256" as const,
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

describe("createCredentialRequest v1.0.2", () => {
  const baseOptions: CredentialRequestOptionsV1_0 = {
    callbacks: mockCallbacks,
    clientId: "test-client-id",
    credential_identifier: "test-credential-identifier",
    issuerIdentifier: "https://issuer.example.com",
    nonce: "test-nonce-123",
    signer: mockSigner,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
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

  it("should return singular proof object (not proofs array)", async () => {
    const result = await createCredentialRequest(baseOptions);

    expect(result).toHaveProperty("proof");
    expect(result).not.toHaveProperty("proofs");
  });

  it("should include explicit proof_type field", async () => {
    const result = await createCredentialRequest(baseOptions);

    expect(result.proof).toHaveProperty("proof_type");
    expect(result.proof.proof_type).toBe("jwt");
  });

  it("should call signJwt with correct parameters (no key_attestation)", async () => {
    await createCredentialRequest(baseOptions);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        jwk: mockSigner.publicJwk,
        typ: "openid4vci-proof+jwt",
        // key_attestation should NOT be present in v1.0.2
      },
      payload: {
        aud: "https://issuer.example.com",
        iat: expect.any(Number),
        iss: "test-client-id",
        nonce: "test-nonce-123",
      },
    });
  });

  it("should NOT include key_attestation in JWT header", async () => {
    await createCredentialRequest(baseOptions);

    const signJwtCall = mockCallbacks.signJwt.mock.calls[0];
    expect(signJwtCall).toBeDefined();
    if (!signJwtCall) throw new Error("signJwtCall is undefined");

    expect(signJwtCall[1].header).not.toHaveProperty("key_attestation");
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
