import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  WalletAttestationOptionsV1_5,
  createWalletAttestationJwt,
} from "../create-wallet-attestation-jwt";

const buildJwt = (header: object, payload: object) =>
  [
    encodeToBase64Url(JSON.stringify(header)),
    encodeToBase64Url(JSON.stringify(payload)),
    "signature",
  ].join(".");

describe("createWalletAttestationJwt v1.5", () => {
  const mockSignJwt = vi.fn();
  const mockJwk = { crv: "P-256", kty: "EC", x: "x-value", y: "y-value" };
  const mockX5c = ["MIICert1Base64==", "MIICert2Base64=="] as [
    string,
    ...string[],
  ];
  const statusExpiresAt = new Date("2099-01-01T00:00:00Z");

  const baseOptions: WalletAttestationOptionsV1_5 = {
    callbacks: { signJwt: mockSignJwt },
    clientStatus: {
      expiresAt: statusExpiresAt,
      statusList: { idx: 7, uri: "https://wp.example.com/status" },
    },
    dpopJwkPublic: mockJwk,
    signer: { alg: "ES256", kid: "test-kid", method: "x5c", x5c: mockX5c },
    walletLink: "https://wallet.example.com",
    walletName: "Test Wallet",
    walletSolutionId: "https://wp.example.com/wallet-solution",
    walletVersion: "1.0.0",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockSignJwt.mockImplementation(async (_signer, { header, payload }) => ({
      jwt: buildJwt(header, payload),
    }));
  });

  it("should sign the v1.5 header and payload without iss and iat", async () => {
    await createWalletAttestationJwt(baseOptions);

    const [, { header, payload }] = mockSignJwt.mock.calls[0] ?? [];
    expect(header).toEqual({
      alg: "ES256",
      kid: "test-kid",
      typ: "oauth-client-attestation+jwt",
      x5c: mockX5c,
    });
    expect(payload).toEqual({
      client_status: {
        exp: dateToSeconds(statusExpiresAt),
        status: {
          status_list: { idx: 7, uri: "https://wp.example.com/status" },
        },
      },
      cnf: { jwk: mockJwk },
      exp: expect.any(Number),
      sub: "https://wp.example.com/wallet-solution",
      wallet_link: "https://wallet.example.com",
      wallet_name: "Test Wallet",
      wallet_version: "1.0.0",
    });
  });

  it("should include optional nbf, certification information and trust_chain", async () => {
    const nbf = new Date();
    await createWalletAttestationJwt({
      ...baseOptions,
      nbf,
      signer: { ...baseOptions.signer, trustChain: ["tc-jwt"] },
      walletSolutionCertificationInformation: "https://wp.example.com/cert",
    });

    const [, { header, payload }] = mockSignJwt.mock.calls[0] ?? [];
    expect(header.trust_chain).toEqual(["tc-jwt"]);
    expect(payload.nbf).toBe(dateToSeconds(nbf));
    expect(payload.wallet_solution_certification_information).toBe(
      "https://wp.example.com/cert",
    );
  });

  it("should reject an expiration longer than 24 hours", async () => {
    await expect(
      createWalletAttestationJwt({
        ...baseOptions,
        expiresAt: addSecondsToDate(new Date(), 86400 + 60),
      }),
    ).rejects.toThrow(ValidationError);
  });

  it("should reject a walletSolutionId that is not a URL", async () => {
    await expect(
      createWalletAttestationJwt({
        ...baseOptions,
        walletSolutionId: "not-a-url",
      }),
    ).rejects.toThrow(ValidationError);
  });
});
