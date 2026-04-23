import {
  createWalletAttestationJwtV1_0,
  createWalletAttestationJwtV1_3,
} from "@pagopa/io-wallet-oauth2";
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

import { WalletProvider } from "../WalletProvider";

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createWalletAttestationJwtV1_0: vi.fn(),
    createWalletAttestationJwtV1_3: vi.fn(),
  };
});

const mockCreateWalletAttestationJwtV1_0 =
  createWalletAttestationJwtV1_0 as MockedFunction<
    typeof createWalletAttestationJwtV1_0
  >;
const mockCreateWalletAttestationJwtV1_3 =
  createWalletAttestationJwtV1_3 as MockedFunction<
    typeof createWalletAttestationJwtV1_3
  >;

describe("WalletProvider v1.0", () => {
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

  describe("routing", () => {
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
});
