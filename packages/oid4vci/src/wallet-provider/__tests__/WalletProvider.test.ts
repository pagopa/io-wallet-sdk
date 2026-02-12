import { Openid4vciWalletProviderOptions } from "@openid4vc/openid4vci";
import { addSecondsToDate } from "@openid4vc/utils";
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

vi.mock("@openid4vc/utils", async () => {
  const actual = await vi.importActual("@openid4vc/utils");
  return {
    ...actual,
    addSecondsToDate: vi.fn(),
  };
});

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

const mockAddSecondsToDate = addSecondsToDate as MockedFunction<
  typeof addSecondsToDate
>;
const mockCreateWalletAttestationJwtV1_0 =
  V1_0.createWalletAttestationJwt as MockedFunction<
    typeof V1_0.createWalletAttestationJwt
  >;
const mockCreateWalletAttestationJwtV1_3 =
  V1_3.createWalletAttestationJwt as MockedFunction<
    typeof V1_3.createWalletAttestationJwt
  >;

describe("WalletProvider", () => {
  let provider: WalletProvider;
  let mockOptions: Openid4vciWalletProviderOptions;
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

    mockOptions = {} as Openid4vciWalletProviderOptions;
    provider = new WalletProvider(mockOptions);

    mockAddSecondsToDate.mockReturnValue(new Date("2025-03-26T00:00:00Z"));
    mockCreateWalletAttestationJwtV1_0.mockResolvedValue("v1.0-jwt-token");
    mockCreateWalletAttestationJwtV1_3.mockResolvedValue("v1.3-jwt-token");
  });

  describe("version routing", () => {
    it("should route to v1.0 implementation when version is V1_0", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      }) as {
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0;
      } & IoWalletSdkConfig;

      const options: V1_0.WalletAttestationOptionsV1_0 = {
        callbacks: { signJwt: mockSignJwt },
        config,
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
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      }) as {
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3;
      } & IoWalletSdkConfig;

      const options: V1_3.WalletAttestationOptionsV1_3 = {
        callbacks: { signJwt: mockSignJwt },
        config,
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
      const config = {
        itWalletSpecsVersion: "v2.0" as unknown as ItWalletSpecsVersion,
      };

      const options = {
        callbacks: { signJwt: mockSignJwt },
        config,
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

  describe("v1.3 routing", () => {
    it("should pass all options to v1.3 implementation including optional fields", async () => {
      const config = new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      }) as {
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3;
      } & IoWalletSdkConfig;

      const nbfDate = new Date("2025-01-01T00:00:00Z");
      const status = {
        status_list: {
          idx: "42",
          uri: "https://status.example.com/list",
        },
      };

      const options: V1_3.WalletAttestationOptionsV1_3 = {
        callbacks: { signJwt: mockSignJwt },
        config,
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
        config,
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

  describe("validation", () => {
    it("should throw WalletProviderError when config is missing", async () => {
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
      ).rejects.toThrow(WalletProviderError);
      await expect(
        provider.createItWalletAttestationJwt(options),
      ).rejects.toThrow("config parameter is required");
    });
  });
});
