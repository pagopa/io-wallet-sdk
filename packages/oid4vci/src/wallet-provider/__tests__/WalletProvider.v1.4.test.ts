import { V1_0, V1_3, V1_4 } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
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
    V1_4: {
      ...actual.V1_4,
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
const mockCreateWalletAttestationJwtV1_4 =
  V1_4.createWalletAttestationJwt as MockedFunction<
    typeof V1_4.createWalletAttestationJwt
  >;

describe("WalletProvider v1.4 routing", () => {
  const mockSignJwt = vi.fn();
  const mockJwk = {
    crv: "P-256",
    kid: "test-key-id",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  };

  const provider = new WalletProvider(
    new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 }),
  );

  const baseSigner: V1_4.WalletAttestationOptionsV1_4["signer"] = {
    alg: "ES256",
    kid: "provider-key-id",
    method: "x5c",
    x5c: ["cert1-base64"] as [string, ...string[]],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateWalletAttestationJwtV1_0.mockResolvedValue("v1.0-jwt-token");
    mockCreateWalletAttestationJwtV1_3.mockResolvedValue("v1.3-jwt-token");
    mockCreateWalletAttestationJwtV1_4.mockResolvedValue("v1.4-jwt-token");
  });

  it("should route to v1.4 implementation when version is V1_4", async () => {
    const options: V1_4.WalletAttestationOptionsV1_4 = {
      callbacks: { signJwt: mockSignJwt },
      dpopJwkPublic: mockJwk,
      issuer: "https://wallet-provider.example.com",
      signer: {
        ...baseSigner,
        x5c: ["cert1-base64", "cert2-base64"] as [string, ...string[]],
      },
      status: {
        status_list: { idx: 2, uri: "https://status.example.com/list" },
      },
      walletLink: "https://wallet.example.com",
      walletName: "Wallet v1.4",
    };

    const result = await provider.createItWalletAttestationJwt(options);

    expect(result).toBe("v1.4-jwt-token");
    expect(mockCreateWalletAttestationJwtV1_4).toHaveBeenCalledTimes(1);
    expect(mockCreateWalletAttestationJwtV1_0).not.toHaveBeenCalled();
    expect(mockCreateWalletAttestationJwtV1_3).not.toHaveBeenCalled();
  });

  it("should pass all options to v1.4 implementation including eudiWalletInfo", async () => {
    const status = {
      status_list: { idx: 42, uri: "https://status.example.com/list" },
    };
    const eudiWalletInfo = {
      general_info: {
        wallet_provider_name: "PagoPA",
        wallet_solution_certification_information: "certification-reference",
        wallet_solution_id: "wallet-solution-id",
        wallet_solution_version: "1.0.0",
      },
    };
    const options: V1_4.WalletAttestationOptionsV1_4 = {
      callbacks: { signJwt: mockSignJwt },
      dpopJwkPublic: mockJwk,
      eudiWalletInfo,
      expiresAt: new Date("2025-06-01T00:00:00Z"),
      issuer: "https://wallet-provider.example.com",
      signer: {
        ...baseSigner,
        trustChain: ["jwt1", "jwt2"] as [string, ...string[]],
        x5c: ["cert1-base64", "cert2-base64"] as [string, ...string[]],
      },
      status,
      walletLink: "https://wallet.example.com",
      walletName: "Premium Wallet",
    };

    await provider.createItWalletAttestationJwt(options);

    expect(mockCreateWalletAttestationJwtV1_4).toHaveBeenCalledWith({
      callbacks: { signJwt: mockSignJwt },
      dpopJwkPublic: mockJwk,
      eudiWalletInfo,
      expiresAt: new Date("2025-06-01T00:00:00Z"),
      issuer: "https://wallet-provider.example.com",
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

  describe("version mismatch", () => {
    const baseOptions = {
      callbacks: { signJwt: vi.fn() },
      dpopJwkPublic: {
        crv: "P-256",
        kid: "test-key-id",
        kty: "EC",
        x: "test-x-value",
        y: "test-y-value",
      },
      issuer: "https://wallet-provider.example.com",
      signer: {
        alg: "ES256",
        kid: "provider-key-id",
        method: "x5c" as const,
        x5c: ["cert1-base64"] as [string, ...string[]],
      },
      status: { status_list: { idx: 1, uri: "https://status.example.com" } },
      walletLink: "https://wallet.example.com",
      walletName: "My Wallet",
    };

    it.each([
      ["walletLink is missing", { ...baseOptions, walletLink: undefined }],
      ["walletName is missing", { ...baseOptions, walletName: undefined }],
      ["status is missing", { ...baseOptions, status: undefined }],
      [
        "v1.3-shaped options are passed (all required fields absent)",
        {
          callbacks: baseOptions.callbacks,
          dpopJwkPublic: baseOptions.dpopJwkPublic,
          issuer: baseOptions.issuer,
          signer: baseOptions.signer,
        },
      ],
    ])("should throw WalletProviderError when %s", async (_, options) => {
      await expect(
        provider.createItWalletAttestationJwt(
          options as unknown as Parameters<
            typeof provider.createItWalletAttestationJwt
          >[0],
        ),
      ).rejects.toThrow(WalletProviderError);
    });
  });
});
