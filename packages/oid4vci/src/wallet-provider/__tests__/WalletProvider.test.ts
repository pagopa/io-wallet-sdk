import { V1_0, V1_3 } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";
import {
  type MockedFunction,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { WalletProviderError } from "../../errors";
import { WalletProvider } from "../WalletProvider";

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    V1_0: {
      ...actual.V1_0,
      createWalletAttestationJwt: vi.fn(),
    },
    V1_3: {
      ...actual.V1_3,
      createWalletAttestationJwt: vi.fn(),
    },
  };
});

const mockCreateWalletAttestationJwtV1_0 =
  V1_0.createWalletAttestationJwt as MockedFunction<
    typeof V1_0.createWalletAttestationJwt
  >;
const mockCreateWalletAttestationJwtV1_3 =
  V1_3.createWalletAttestationJwt as MockedFunction<
    typeof V1_3.createWalletAttestationJwt
  >;

describe("WalletProvider", () => {
  const mockSignJwt = vi.fn();

  const mockJwk = {
    crv: "P-256",
    kid: "test-key-id",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateWalletAttestationJwtV1_0.mockResolvedValue("v1.0-jwt-token");
    mockCreateWalletAttestationJwtV1_3.mockResolvedValue("v1.3-jwt-token");
  });

  describe("version routing", () => {
    it("should route to v1.0 implementation when version is V1_0", async () => {
      const provider = new WalletProvider(
        new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
        }),
      );

      const options: V1_0.WalletAttestationOptionsV1_0 = {
        authenticatorAssuranceLevel: "aal1",
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "federation",
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        },
      };

      const result = await provider.createItWalletAttestationJwt(options);

      expect(result).toBe("v1.0-jwt-token");
      expect(mockCreateWalletAttestationJwtV1_0).toHaveBeenCalledTimes(1);
      expect(mockCreateWalletAttestationJwtV1_3).not.toHaveBeenCalled();
    });

    it("should route to v1.3 implementation when version is V1_3", async () => {
      const provider = new WalletProvider(
        new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
        }),
      );

      const options: V1_3.WalletAttestationOptionsV1_3 = {
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "x5c",
          x5c: ["cert1-base64", "cert2-base64"] as [string, ...string[]],
        },
      };

      const result = await provider.createItWalletAttestationJwt(options);

      expect(result).toBe("v1.3-jwt-token");
      expect(mockCreateWalletAttestationJwtV1_3).toHaveBeenCalledTimes(1);
      expect(mockCreateWalletAttestationJwtV1_0).not.toHaveBeenCalled();
    });

    it("should throw ItWalletSpecsVersionError for unsupported version", async () => {
      const invalidConfig = {
        isVersion: vi.fn(),
        itWalletSpecsVersion: "v2.0" as unknown as ItWalletSpecsVersion,
      } as unknown as IoWalletSdkConfig;
      const provider = new WalletProvider(invalidConfig);

      const options = {
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "federation",
          trustChain: ["jwt1"],
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any;

      await expect(
        provider.createItWalletAttestationJwt(options),
      ).rejects.toThrow(ItWalletSpecsVersionError);
    });
  });

  describe("version mismatch", () => {
    it("should throw WalletProviderError when options signer method mismatches configured version", async () => {
      const provider = new WalletProvider(
        new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
        }),
      );

      const v1_3Options: V1_3.WalletAttestationOptionsV1_3 = {
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        issuer: "https://wallet-provider.example.com",
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "x5c",
          x5c: ["cert1-base64"] as [string, ...string[]],
        },
      };

      await expect(
        provider.createItWalletAttestationJwt(
          v1_3Options as Parameters<
            typeof provider.createItWalletAttestationJwt
          >[0],
        ),
      ).rejects.toThrow(WalletProviderError);
    });
  });

  describe("v1.3 routing", () => {
    it("should pass all options to v1.3 implementation including optional fields", async () => {
      const provider = new WalletProvider(
        new IoWalletSdkConfig({
          itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
        }),
      );

      const nbfDate = new Date("2025-01-01T00:00:00Z");
      const status = {
        status_list: {
          idx: 42,
          uri: "https://status.example.com/list",
        },
      };

      const options: V1_3.WalletAttestationOptionsV1_3 = {
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-06-01T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        nbf: nbfDate,
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "x5c",
          trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
          x5c: ["cert1-base64", "cert2-base64"] as [string, ...string[]],
        },
        status,
        walletLink: "https://wallet.example.com",
        walletName: "Premium Wallet",
      };

      await provider.createItWalletAttestationJwt(options);

      expect(mockCreateWalletAttestationJwtV1_3).toHaveBeenCalledWith({
        callbacks: { signJwt: mockSignJwt },
        dpopJwkPublic: mockJwk,
        expiresAt: new Date("2025-06-01T00:00:00Z"),
        issuer: "https://wallet-provider.example.com",
        nbf: nbfDate,
        signer: {
          alg: "ES256",
          kid: "provider-key-id",
          method: "x5c",
          trustChain: ["jwt1", "jwt2"],
          x5c: ["cert1-base64", "cert2-base64"],
        },
        status,
        walletLink: "https://wallet.example.com",
        walletName: "Premium Wallet",
      });
    });
  });
});
