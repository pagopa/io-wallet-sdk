import { Jwk } from "@openid4vc/oauth2";
import { Openid4vciWalletProviderOptions } from "@openid4vc/openid4vci";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";
import {
  type MockedFunction,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { WalletProviderError } from "../../errors";
import { KeyAttestationOptions, WalletProvider } from "../WalletProvider";
import { KeyAttestationStatus } from "../z-key-attestation";

vi.mock("@openid4vc/utils", async () => {
  const actual = await vi.importActual("@openid4vc/utils");
  return {
    ...actual,
    addSecondsToDate: vi.fn(),
    dateToSeconds: vi.fn(),
  };
});

const mockAddSecondsToDate = addSecondsToDate as MockedFunction<
  typeof addSecondsToDate
>;
const mockDateToSeconds = dateToSeconds as MockedFunction<typeof dateToSeconds>;

/* eslint-disable max-lines-per-function */
describe("createItKeyAttestationJwt", () => {
  let provider: WalletProvider;
  let mockSignJwt: MockedFunction<
    (signer: unknown, data: unknown) => Promise<{ jwt: string; signerJwk: Jwk }>
  >;
  let mockAttestedKeys: [Jwk];
  let mockStatus: KeyAttestationStatus;
  let mockKeyAttestationOptions: KeyAttestationOptions;

  const setupMockAttestedKeys = (): [Jwk] => [
    {
      crv: "P-256",
      kty: "EC",
      x: "4HNptI-xr2pjyRJKGMnz4WmdnQD_uJSq4R95Nj98b44",
      y: "LIZnSB39vFJhYgS3k7jXE4r3-CoGFQwZtPBIRqpNlrg",
    },
  ];

  const setupMockStatus = (): KeyAttestationStatus => ({
    status_list: {
      idx: 412,
      uri: "https://revocation_url/statuslists/1",
    },
  });

  const setupMockOptions = (
    attestedKeys: [Jwk],
    status: KeyAttestationStatus,
    signJwt: MockedFunction<
      (
        signer: unknown,
        data: unknown,
      ) => Promise<{ jwt: string; signerJwk: Jwk }>
    >,
  ): KeyAttestationOptions => ({
    attestedKeys,
    callbacks: {
      signJwt,
    },
    issuer: "https://wallet-provider.example.org",
    keyStorage: ["iso_18045_moderate"],
    signer: {
      alg: "ES256",
      kid: "wallet-provider-kid",
      method: "x5c",
      x5c: ["cert1-base64", "cert2-base64"],
    },
    status,
    userAuthentication: ["iso_18045_moderate"],
  });

  beforeEach(() => {
    vi.restoreAllMocks();

    const mockOptions = {} as Openid4vciWalletProviderOptions;
    provider = new WalletProvider(mockOptions);

    mockAttestedKeys = setupMockAttestedKeys();

    mockSignJwt = vi.fn().mockResolvedValue({
      jwt: "mocked-key-attestation-jwt",
      signerJwk: mockAttestedKeys[0],
    });

    mockStatus = setupMockStatus();

    mockKeyAttestationOptions = setupMockOptions(
      mockAttestedKeys,
      mockStatus,
      mockSignJwt,
    );

    mockAddSecondsToDate.mockReturnValue(new Date("2024-12-31T23:59:59Z"));
    mockDateToSeconds.mockImplementation((date?: Date) =>
      Math.floor((date ?? new Date()).getTime() / 1000),
    );
  });

  it("should create key attestation JWT with all provided options", async () => {
    const expiresAt = new Date("2024-12-31T23:59:59Z");
    const issuedAt = new Date("2024-01-01T00:00:00Z");
    const expiresAtSeconds = Math.floor(expiresAt.getTime() / 1000);
    const issuedAtSeconds = Math.floor(issuedAt.getTime() / 1000);

    const options = {
      ...mockKeyAttestationOptions,
      certification: "GP",
      expiresAt,
      issuedAt,
      trustChain: ["trust-jwt-1", "trust-jwt-2"] as [string, string],
    };

    const result = await provider.createItKeyAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      {
        alg: "ES256",
        kid: "wallet-provider-kid",
        method: "x5c",
        x5c: ["cert1-base64", "cert2-base64"],
      },
      {
        header: {
          alg: "ES256",
          kid: "wallet-provider-kid",
          trust_chain: ["trust-jwt-1", "trust-jwt-2"],
          typ: "key-attestation+jwt",
          x5c: ["cert1-base64", "cert2-base64"],
        },
        payload: {
          attested_keys: mockAttestedKeys,
          certification: "GP",
          exp: expiresAtSeconds,
          iat: issuedAtSeconds,
          iss: "https://wallet-provider.example.org",
          key_storage: ["iso_18045_moderate"],
          status: mockStatus,
          user_authentication: ["iso_18045_moderate"],
        },
      },
    );

    expect(result).toBe("mocked-key-attestation-jwt");
  });

  it("should create key attestation JWT with minimal required options", async () => {
    const result = await provider.createItKeyAttestationJwt(
      mockKeyAttestationOptions,
    );

    expect(mockSignJwt).toHaveBeenCalledWith(
      {
        alg: "ES256",
        kid: "wallet-provider-kid",
        method: "x5c",
        x5c: ["cert1-base64", "cert2-base64"],
      },
      {
        header: {
          alg: "ES256",
          kid: "wallet-provider-kid",
          typ: "key-attestation+jwt",
          x5c: ["cert1-base64", "cert2-base64"],
        },
        payload: {
          attested_keys: mockAttestedKeys,
          exp: expect.any(Number),
          iat: expect.any(Number),
          iss: "https://wallet-provider.example.org",
          key_storage: ["iso_18045_moderate"],
          status: mockStatus,
          user_authentication: ["iso_18045_moderate"],
        },
      },
    );

    expect(result).toBe("mocked-key-attestation-jwt");
  });

  it("should use default expiration when expiresAt is not provided", async () => {
    const expectedExpiration = new Date("2024-12-31T23:59:59Z");

    mockAddSecondsToDate.mockReturnValue(expectedExpiration);

    await provider.createItKeyAttestationJwt(mockKeyAttestationOptions);

    expect(mockAddSecondsToDate).toHaveBeenCalledWith(
      expect.any(Date),
      3600 * 24 * 360,
    );
  });

  it("should use default issuedAt when not provided", async () => {
    await provider.createItKeyAttestationJwt(mockKeyAttestationOptions);

    expect(mockDateToSeconds).toHaveBeenCalledWith(expect.any(Date));
  });

  it("should support multiple attested keys", async () => {
    const multipleKeys: [Jwk, Jwk] = [
      mockAttestedKeys[0],
      {
        crv: "P-256",
        kty: "EC",
        x: "different-x-value",
        y: "different-y-value",
      },
    ];

    const options = {
      ...mockKeyAttestationOptions,
      attestedKeys: multipleKeys,
    };

    await provider.createItKeyAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        payload: expect.objectContaining({
          attested_keys: multipleKeys,
        }),
      }),
    );
  });

  it("should support different key storage levels", async () => {
    const options = {
      ...mockKeyAttestationOptions,
      keyStorage: ["iso_18045_high", "iso_18045_basic"] as [string, string],
    };

    await provider.createItKeyAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        payload: expect.objectContaining({
          key_storage: ["iso_18045_high", "iso_18045_basic"],
        }),
      }),
    );
  });

  it("should support different user authentication levels", async () => {
    const options = {
      ...mockKeyAttestationOptions,
      userAuthentication: ["iso_18045_high"] as [string],
    };

    await provider.createItKeyAttestationJwt(options);

    expect(mockSignJwt).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        payload: expect.objectContaining({
          user_authentication: ["iso_18045_high"],
        }),
      }),
    );
  });

  it("should include status list structure in payload", async () => {
    await provider.createItKeyAttestationJwt(mockKeyAttestationOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        payload: expect.objectContaining({
          status: {
            status_list: {
              idx: 412,
              uri: "https://revocation_url/statuslists/1",
            },
          },
        }),
      }),
    );
  });

  it("should not include certification when not provided", async () => {
    await provider.createItKeyAttestationJwt(mockKeyAttestationOptions);

    const callArgs = mockSignJwt.mock.calls[0]?.[1] as
      | {
          payload: Record<string, unknown>;
        }
      | undefined;
    expect(callArgs?.payload).not.toHaveProperty("certification");
  });

  it("should not include trust_chain when not provided", async () => {
    await provider.createItKeyAttestationJwt(mockKeyAttestationOptions);

    const callArgs = mockSignJwt.mock.calls[0]?.[1] as
      | {
          header: Record<string, unknown>;
        }
      | undefined;
    expect(callArgs?.header).not.toHaveProperty("trust_chain");
  });

  it("should propagate errors from signJwt callback", async () => {
    const error = new Error("JWT signing failed");
    mockSignJwt.mockRejectedValue(error);

    await expect(
      provider.createItKeyAttestationJwt(mockKeyAttestationOptions),
    ).rejects.toThrow(WalletProviderError);

    await expect(
      provider.createItKeyAttestationJwt(mockKeyAttestationOptions),
    ).rejects.toThrow(
      "Failed to create key attestation JWT: JWT signing failed",
    );
  });

  it("should handle non-Error objects in catch block", async () => {
    mockSignJwt.mockRejectedValue("string error");

    await expect(
      provider.createItKeyAttestationJwt(mockKeyAttestationOptions),
    ).rejects.toThrow(WalletProviderError);

    await expect(
      provider.createItKeyAttestationJwt(mockKeyAttestationOptions),
    ).rejects.toThrow("Failed to create key attestation JWT: string error");
  });
});
