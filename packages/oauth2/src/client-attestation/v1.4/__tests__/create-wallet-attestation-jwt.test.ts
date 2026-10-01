import {
  ValidationError,
  dateToSeconds,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ClientAttestationError } from "../../../errors";
import {
  WalletAttestationOptionsV1_4,
  createWalletAttestationJwt,
} from "../create-wallet-attestation-jwt";

const buildJwt = (header: object, payload: object) =>
  [
    encodeToBase64Url(JSON.stringify(header)),
    encodeToBase64Url(JSON.stringify(payload)),
    "signature",
  ].join(".");

describe("createWalletAttestationJwt v1.4", () => {
  const mockHash = vi.fn();
  const mockSignJwt = vi.fn();
  const mockJwkThumbprint = "AQID";

  const expiresAt = new Date(Date.now() + 3600 * 1000);

  const mockJwk = {
    crv: "P-256",
    kid: "test-key-id",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  };

  const mockX5c = ["MIICertificate1Base64==", "MIICertificate2Base64=="] as [
    string,
    ...string[],
  ];

  const baseOptions: WalletAttestationOptionsV1_4 = {
    callbacks: { hash: mockHash, signJwt: mockSignJwt },
    dpopJwkPublic: mockJwk,
    expiresAt,
    issuer: "https://wallet-provider.example.com",
    signer: {
      alg: "ES256",
      kid: "test-kid",
      method: "x5c",
      x5c: mockX5c,
    },
    walletLink: "https://wallet.example.com",
    walletName: "Test Wallet",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockHash.mockResolvedValue(new Uint8Array([1, 2, 3]));
    mockSignJwt.mockImplementation(async (_signer, { header, payload }) => ({
      jwt: buildJwt(header, payload),
    }));
  });

  it("should create a valid wallet attestation JWT with required v1.4 claims", async () => {
    await createWalletAttestationJwt(baseOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(
      baseOptions.signer,
      expect.objectContaining({
        header: {
          alg: "ES256",
          kid: "test-kid",
          typ: "oauth-client-attestation+jwt",
          x5c: mockX5c,
        },
        payload: expect.objectContaining({
          cnf: { jwk: mockJwk },
          exp: dateToSeconds(expiresAt),
          iat: expect.any(Number),
          iss: "https://wallet-provider.example.com",
          sub: mockJwkThumbprint,
          wallet_link: "https://wallet.example.com",
          wallet_name: "Test Wallet",
        }),
      }),
    );
  });

  it("should not include the status and eudi_wallet_info claims removed in v1.4.6", async () => {
    await createWalletAttestationJwt(baseOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(
      baseOptions.signer,
      expect.objectContaining({
        payload: expect.not.objectContaining({
          eudi_wallet_info: expect.anything(),
          status: expect.anything(),
        }),
      }),
    );
  });

  it("should create a valid wallet attestation JWT when the DPoP JWK has no kid", async () => {
    const options = {
      ...baseOptions,
      dpopJwkPublic: {
        crv: "P-256",
        kty: "EC",
        x: "test-x-value",
        y: "test-y-value",
      },
    };

    await createWalletAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      baseOptions.signer,
      expect.objectContaining({
        payload: expect.objectContaining({
          cnf: { jwk: options.dpopJwkPublic },
          sub: mockJwkThumbprint,
        }),
      }),
    );
  });

  it("should fail when walletLink is missing", async () => {
    const options = {
      ...baseOptions,
      walletLink: undefined,
    } as unknown as WalletAttestationOptionsV1_4;

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should fail when walletName is missing", async () => {
    const options = {
      ...baseOptions,
      walletName: undefined,
    } as unknown as WalletAttestationOptionsV1_4;

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should fail when expiresAt is not after iat", async () => {
    const options: WalletAttestationOptionsV1_4 = {
      ...baseOptions,
      expiresAt: new Date(Date.now() - 1000),
    };

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      /exp must be after iat/,
    );
  });

  it("should fail when expiresAt is more than 24 hours after iat", async () => {
    const options: WalletAttestationOptionsV1_4 = {
      ...baseOptions,
      expiresAt: new Date(Date.now() + (86400 + 60) * 1000),
    };

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      /exp must not be more than 24 hours after iat/,
    );
  });

  it("should accept an expiration exactly at the 24 hour boundary", async () => {
    const options: WalletAttestationOptionsV1_4 = {
      ...baseOptions,
      expiresAt: new Date(Date.now() + 86400 * 1000 - 1000),
    };

    await expect(createWalletAttestationJwt(options)).resolves.toBeTypeOf(
      "string",
    );
  });

  it("should fail when nbf is not before exp", async () => {
    const options: WalletAttestationOptionsV1_4 = {
      ...baseOptions,
      nbf: new Date(expiresAt.getTime() + 1000),
    };

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      /nbf must be before exp/,
    );
  });

  it("should wrap unexpected signing errors in ClientAttestationError", async () => {
    mockSignJwt.mockRejectedValue(new Error("Crypto module crashed"));

    await expect(createWalletAttestationJwt(baseOptions)).rejects.toThrow(
      ClientAttestationError,
    );
    await expect(createWalletAttestationJwt(baseOptions)).rejects.toThrow(
      /Unexpected error during wallet attestation creation/,
    );
  });
});
