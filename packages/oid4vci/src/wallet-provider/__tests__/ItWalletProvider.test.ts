import { Openid4vciWalletProviderOptions } from "@openid4vc/openid4vci";
import { addSecondsToDate } from "@openid4vc/utils";
import {
  type MockedFunction,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  ItWalletProvider,
  WalletAttestationOptions,
} from "../ItWalletProvider";

vi.mock("@openid4vc/utils", () => ({
  addSecondsToDate: vi.fn(),
}));

const mockAddSecondsToDate = addSecondsToDate as MockedFunction<
  typeof addSecondsToDate
>;

describe("ItWalletProvider", () => {
  let provider: ItWalletProvider;
  let mockOptions: Openid4vciWalletProviderOptions;
  let mockCreateWalletAttestationJwt: MockedFunction<
    typeof ItWalletProvider.prototype.createWalletAttestationJwt
  >;

  beforeEach(() => {
    vi.clearAllMocks();

    mockOptions = {} as Openid4vciWalletProviderOptions;

    provider = new ItWalletProvider(mockOptions);

    mockCreateWalletAttestationJwt = vi
      .fn()
      .mockResolvedValue("mocked-jwt-token");
    provider.createWalletAttestationJwt = mockCreateWalletAttestationJwt;

    mockAddSecondsToDate.mockReturnValue(new Date("2024-12-31T23:59:59Z"));
  });

  describe("createItWalletAttestationJwt", () => {
    let mockWalletAttestationOptions: WalletAttestationOptions;

    beforeEach(() => {
      mockWalletAttestationOptions = {
        dpopJwkPublic: {
          crv: "P-256",
          kid: "test-key-id",
          kty: "EC",
          x: "test-x-value",
          y: "test-y-value",
        },
        expiresAt: new Date("2024-12-31T23:59:59Z"),
        issuer: "https://wallet-provider.example.com",
        signer: {
          trustChain: ["trust-anchor-jwt", "intermediate-jwt"],
          walletProviderJwkPublicKid: "provider-key-id",
        },
        walletLink: "https://wallet.example.com",
        walletName: "Test Wallet",
      };
    });

    it("should create wallet attestation JWT with all provided options", async () => {
      const result = await provider.createItWalletAttestationJwt(
        mockWalletAttestationOptions
      );

      expect(mockCreateWalletAttestationJwt).toHaveBeenCalledWith({
        clientId: mockWalletAttestationOptions.dpopJwkPublic.kid,
        confirmation: {
          jwk: mockWalletAttestationOptions.dpopJwkPublic,
        },
        expiresAt: mockWalletAttestationOptions.expiresAt,
        issuer: mockWalletAttestationOptions.issuer,
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "federation",
          trustChain: ["trust-anchor-jwt", "intermediate-jwt"],
        },
        walletLink: "https://wallet.example.com",
        walletName: "Test Wallet",
      });

      expect(result).toBe("mocked-jwt-token");
    });

    it("should use default expiration when expiresAt is not provided", async () => {
      const optionsWithoutExpiration = { ...mockWalletAttestationOptions };
      delete optionsWithoutExpiration.expiresAt;

      await provider.createItWalletAttestationJwt(optionsWithoutExpiration);

      expect(mockAddSecondsToDate).toHaveBeenCalledWith(
        expect.any(Date),
        3600 * 24 * 60 * 60
      );
      expect(mockCreateWalletAttestationJwt).toHaveBeenCalledWith({
        clientId: mockWalletAttestationOptions.dpopJwkPublic.kid,
        confirmation: {
          jwk: mockWalletAttestationOptions.dpopJwkPublic,
        },
        expiresAt: new Date("2024-12-31T23:59:59Z"),
        issuer: mockWalletAttestationOptions.issuer,
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "federation",
          trustChain: ["trust-anchor-jwt", "intermediate-jwt"],
        },
        walletLink: "https://wallet.example.com",
        walletName: "Test Wallet",
      });
    });

    it("should work without optional walletName and walletLink", async () => {
      const minimalOptions = {
        dpopJwkPublic: mockWalletAttestationOptions.dpopJwkPublic,
        issuer: mockWalletAttestationOptions.issuer,
        signer: mockWalletAttestationOptions.signer,
      };

      await provider.createItWalletAttestationJwt(minimalOptions);

      expect(mockCreateWalletAttestationJwt).toHaveBeenCalledWith({
        clientId: mockWalletAttestationOptions.dpopJwkPublic.kid,
        confirmation: {
          jwk: mockWalletAttestationOptions.dpopJwkPublic,
        },
        expiresAt: new Date("2024-12-31T23:59:59Z"),
        issuer: mockWalletAttestationOptions.issuer,
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "federation",
          trustChain: ["trust-anchor-jwt", "intermediate-jwt"],
        },
        walletLink: undefined,
        walletName: undefined,
      });
    });

    it("should use dpopJwkPublic.kid as clientId", async () => {
      const customKidOptions = {
        ...mockWalletAttestationOptions,
        dpopJwkPublic: {
          ...mockWalletAttestationOptions.dpopJwkPublic,
          kid: "custom-kid-value",
        },
      };

      await provider.createItWalletAttestationJwt(customKidOptions);

      expect(mockCreateWalletAttestationJwt).toHaveBeenCalledWith(
        expect.objectContaining({
          clientId: "custom-kid-value",
        })
      );
    });

    it("should always use ES256 algorithm and federation method", async () => {
      await provider.createItWalletAttestationJwt(mockWalletAttestationOptions);

      expect(mockCreateWalletAttestationJwt).toHaveBeenCalledWith(
        expect.objectContaining({
          signer: expect.objectContaining({
            alg: "ES256",
            method: "federation",
          }),
        })
      );
    });

    it("should propagate errors from createWalletAttestationJwt", async () => {
      const error = new Error("JWT creation failed");
      mockCreateWalletAttestationJwt.mockRejectedValue(error);

      await expect(
        provider.createItWalletAttestationJwt(mockWalletAttestationOptions)
      ).rejects.toThrow("JWT creation failed");
    });
  });
});
