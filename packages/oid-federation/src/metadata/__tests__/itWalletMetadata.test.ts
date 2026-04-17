import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import {
  isItWalletMetadataVersion,
  parseItWalletMetadataForVersion,
} from "../itWalletMetadata";

const validV1_0Metadata = {
  wallet_provider: {
    jwks_uri: "https://wallet-provider.example.com/jwks.json",
    signed_jwks_uri: "https://wallet-provider.example.com/signed-jwks.jwt",
  },
};

const validV1_3Metadata = {
  wallet_solution: {
    logo_uri: "https://wallet-solution.example.com/logo.svg",
    wallet_metadata: {
      authorization_endpoint: "https://wallet-solution.example.com/authorize",
      client_id_prefixes_supported: ["openid_federation"],
      credential_offer_endpoint:
        "https://wallet-solution.example.com/credential-offer",
      request_object_signing_alg_values_supported: ["ES256"],
      response_modes_supported: ["query"],
      response_types_supported: ["vp_token"],
      vp_formats_supported: {
        "dc+sd-jwt": {},
      },
      wallet_name: "Example Wallet",
    },
  },
};

describe("isItWalletMetadataVersion", () => {
  it("should identify valid v1.0 metadata", () => {
    expect(
      isItWalletMetadataVersion(validV1_0Metadata, ItWalletSpecsVersion.V1_0),
    ).toBe(true);
  });

  it("should identify valid v1.3 metadata", () => {
    expect(
      isItWalletMetadataVersion(validV1_3Metadata, ItWalletSpecsVersion.V1_3),
    ).toBe(true);
  });

  it("should reject metadata for a different supported version", () => {
    expect(
      isItWalletMetadataVersion(validV1_0Metadata, ItWalletSpecsVersion.V1_3),
    ).toBe(false);
    expect(
      isItWalletMetadataVersion(validV1_3Metadata, ItWalletSpecsVersion.V1_0),
    ).toBe(false);
  });

  it("should throw for an unsupported version", () => {
    expect(() =>
      isItWalletMetadataVersion(validV1_0Metadata, "9.9.9" as never),
    ).toThrow(ItWalletSpecsVersionError);
  });
});

describe("parseItWalletMetadataForVersion", () => {
  it("should parse valid v1.0 metadata", () => {
    expect(
      parseItWalletMetadataForVersion(
        validV1_0Metadata,
        ItWalletSpecsVersion.V1_0,
      ),
    ).toEqual(validV1_0Metadata);
  });

  it("should parse valid v1.3 metadata", () => {
    expect(
      parseItWalletMetadataForVersion(
        validV1_3Metadata,
        ItWalletSpecsVersion.V1_3,
      ),
    ).toEqual(validV1_3Metadata);
  });

  it("should reject metadata for a different supported version", () => {
    expect(() =>
      parseItWalletMetadataForVersion(
        validV1_0Metadata,
        ItWalletSpecsVersion.V1_3,
      ),
    ).toThrow(/invalid v1\.3 metadata provided/);

    expect(() =>
      parseItWalletMetadataForVersion(
        validV1_3Metadata,
        ItWalletSpecsVersion.V1_0,
      ),
    ).toThrow(/invalid v1\.0 metadata provided/);
  });

  it("should throw for an unsupported version", () => {
    expect(() =>
      parseItWalletMetadataForVersion(validV1_0Metadata, "9.9.9" as never),
    ).toThrow(ItWalletSpecsVersionError);
  });
});
