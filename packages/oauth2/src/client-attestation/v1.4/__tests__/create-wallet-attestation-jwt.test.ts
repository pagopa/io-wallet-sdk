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

describe("createWalletAttestationJwt v1.4", () => {
  const mockSignJwt = vi.fn();

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
    callbacks: { signJwt: mockSignJwt },
    dpopJwkPublic: mockJwk,
    expiresAt: new Date("2025-01-25T00:00:00Z"),
    issuer: "https://wallet-provider.example.com",
    signer: {
      alg: "ES256",
      kid: "test-kid",
      method: "x5c",
      x5c: mockX5c,
    },
    status: {
      status_list: {
        idx: 7,
        uri: "https://status.example.com/list",
      },
    },
    walletLink: "https://wallet.example.com",
    walletName: "Test Wallet",
  };

  const buildJwt = (header: object, payload: object) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  beforeEach(() => {
    vi.clearAllMocks();
    mockSignJwt.mockImplementation(async (_signer, { header, payload }) => ({
      jwt: buildJwt(header, payload),
    }));
  });

  it("should create a valid wallet attestation JWT with required v1.4 claims", async () => {
    const result = await createWalletAttestationJwt(baseOptions);

    expect(result).toBeDefined();
    expect(typeof result).toBe("string");
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
          exp: dateToSeconds(new Date("2025-01-25T00:00:00Z")),
          iat: expect.any(Number),
          iss: "https://wallet-provider.example.com",
          status: {
            status_list: {
              idx: 7,
              uri: "https://status.example.com/list",
            },
          },
          sub: "test-key-id",
          wallet_link: "https://wallet.example.com",
          wallet_name: "Test Wallet",
        }),
      }),
    );
  });

  it("should create a valid wallet attestation JWT without eudi_wallet_info", async () => {
    await createWalletAttestationJwt(baseOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(
      baseOptions.signer,
      expect.objectContaining({
        payload: expect.not.objectContaining({
          eudi_wallet_info: expect.anything(),
        }),
      }),
    );
  });

  it("should create a valid wallet attestation JWT with eudi_wallet_info", async () => {
    const options: WalletAttestationOptionsV1_4 = {
      ...baseOptions,
      eudiWalletInfo: {
        general_info: {
          wallet_provider_name: "PagoPA",
          wallet_solution_certification_information:
            "https://certification-reference.example.it",
          wallet_solution_id: "wallet-solution-id",
          wallet_solution_version: "1.0.0",
        },
      },
    };

    await createWalletAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      options.signer,
      expect.objectContaining({
        payload: expect.objectContaining({
          eudi_wallet_info: options.eudiWalletInfo,
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

  it("should fail when status is missing", async () => {
    const options = {
      ...baseOptions,
      status: undefined,
    } as unknown as WalletAttestationOptionsV1_4;

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should fail when eudi_wallet_info is malformed", async () => {
    const options = {
      ...baseOptions,
      eudiWalletInfo: {
        general_info: {
          wallet_provider_name: "PagoPA",
        },
      },
    } as unknown as WalletAttestationOptionsV1_4;

    await expect(createWalletAttestationJwt(options)).rejects.toThrow(
      ValidationError,
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
