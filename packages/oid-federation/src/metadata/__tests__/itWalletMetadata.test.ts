import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
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

const validV1_4Metadata = {
  wallet_solution: {
    logo_uri: "https://wallet-solution.example.com/logo.svg",
    wallet_metadata: {
      authorization_endpoint: "https://wallet-solution.example.com/authorize",
      client_id_prefixes_supported: ["openid_federation"],
      credential_offer_endpoint:
        "https://wallet-solution.example.com/credential-offer",
      request_object_signing_alg_values_supported: ["ES256"],
      vp_formats_supported: {
        "dc+sd-jwt": {},
      },
      wallet_name: "Example Wallet",
    },
  },
};

const federationEntityMetadataWithoutUris = {
  contacts: ["info@pagopa.it"],
  federation_resolve_endpoint: "https://wallet.example.com/resolve",
  logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
  organization_name: "PagoPa S.p.A.",
  policy_uri: "https://io.italia.it/privacy-policy",
  tos_uri: "https://io.italia.it/privacy-policy",
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

  it("should identify valid v1.4 metadata", () => {
    expect(
      isItWalletMetadataVersion(validV1_4Metadata, ItWalletSpecsVersion.V1_4),
    ).toBe(true);
  });

  it("should reject metadata for a different supported version", () => {
    expect(
      isItWalletMetadataVersion(validV1_0Metadata, ItWalletSpecsVersion.V1_3),
    ).toBe(false);
    expect(
      isItWalletMetadataVersion(validV1_3Metadata, ItWalletSpecsVersion.V1_0),
    ).toBe(false);
    expect(
      isItWalletMetadataVersion(validV1_0Metadata, ItWalletSpecsVersion.V1_4),
    ).toBe(false);
    expect(
      isItWalletMetadataVersion(validV1_4Metadata, ItWalletSpecsVersion.V1_3),
    ).toBe(false);
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

  it("should parse valid v1.4 metadata", () => {
    expect(
      parseItWalletMetadataForVersion(
        validV1_4Metadata,
        ItWalletSpecsVersion.V1_4,
      ),
    ).toEqual(validV1_4Metadata);
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
        validV1_0Metadata,
        ItWalletSpecsVersion.V1_4,
      ),
    ).toThrow(/invalid v1\.4 metadata provided/);

    expect(() =>
      parseItWalletMetadataForVersion(
        validV1_3Metadata,
        ItWalletSpecsVersion.V1_0,
      ),
    ).toThrow(/invalid v1\.0 metadata provided/);

    expect(() =>
      parseItWalletMetadataForVersion(
        validV1_4Metadata,
        ItWalletSpecsVersion.V1_3,
      ),
    ).toThrow(/invalid v1\.3 metadata provided/);
  });
});

describe("v1.4 federation_entity metadata", () => {
  it.each([
    {
      expectedMetadata: {
        federation_entity: {
          ...federationEntityMetadataWithoutUris,
          homepage_uri: "https://io.italia.it",
        },
      },
      label: "homepage_uri",
    },
    {
      expectedMetadata: {
        federation_entity: {
          ...federationEntityMetadataWithoutUris,
          organization_uri: "https://www.pagopa.it",
        },
      },
      label: "organization_uri",
    },
    {
      expectedMetadata: {
        federation_entity: {
          ...federationEntityMetadataWithoutUris,
          homepage_uri: "https://io.italia.it",
          organization_uri: "https://www.pagopa.it",
        },
      },
      label: "both URI claims",
    },
  ])(
    "should parse v1.4 federation_entity metadata with $label",
    ({ expectedMetadata }) => {
      expect(
        parseItWalletMetadataForVersion(
          expectedMetadata,
          ItWalletSpecsVersion.V1_4,
        ),
      ).toEqual(expectedMetadata);
    },
  );

  it("should reject v1.4 federation_entity metadata without homepage_uri and organization_uri", () => {
    expect(() =>
      parseItWalletMetadataForVersion(
        { federation_entity: federationEntityMetadataWithoutUris },
        ItWalletSpecsVersion.V1_4,
      ),
    ).toThrow(/at least one of homepage_uri or organization_uri is required/);
  });

  it.each([
    {
      federationEntityMetadata: {
        ...federationEntityMetadataWithoutUris,
        homepage_uri: "not-a-url",
      },
      label: "homepage_uri",
    },
    {
      federationEntityMetadata: {
        ...federationEntityMetadataWithoutUris,
        organization_uri: "not-a-url",
      },
      label: "organization_uri",
    },
  ])(
    "should reject invalid v1.4 $label values",
    ({ federationEntityMetadata }) => {
      expect(() =>
        parseItWalletMetadataForVersion(
          { federation_entity: federationEntityMetadata },
          ItWalletSpecsVersion.V1_4,
        ),
      ).toThrow(/invalid v1\.4 metadata provided/);
    },
  );

  it.each([ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3])(
    "should keep accepting federation_entity metadata without URI claims for %s",
    (version) => {
      const metadata = {
        federation_entity: federationEntityMetadataWithoutUris,
      };

      expect(parseItWalletMetadataForVersion(metadata, version)).toEqual(
        metadata,
      );
    },
  );
});
