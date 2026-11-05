import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import {
  isItWalletMetadataVersion,
  itWalletMetadataSchema,
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

const validAptitudeMetadata = {
  oauth_authorization_server: {
    authorization_endpoint: "https://as.example.com/authorize",
    client_attestation_pop_methods_supported: ["dpop_combined"],
    client_attestation_signing_alg_values_supported: ["ES256"],
    dpop_signing_alg_values_supported: ["ES256"],
    issuer: "https://as.example.com",
    pushed_authorization_request_endpoint: "https://as.example.com/par",
    token_endpoint: "https://as.example.com/token",
    token_endpoint_auth_methods_supported: ["attest_jwt_client_auth_dpop"],
  },
  openid_credential_issuer: {
    authorization_servers: ["https://as.example.com"],
    credential_configurations_supported: {
      "eu.europa.ec.eudi.pid.1": {
        format: "dc+sd-jwt",
        vct: "urn:eudi:pid:1",
      },
    },
    credential_endpoint: "https://issuer.example.com/credential",
    credential_issuer: "https://issuer.example.com",
    issuer_info: [
      { data: "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", format: "registration_cert" },
    ],
    nonce_endpoint: "https://issuer.example.com/nonce",
  },
};

describe("itWalletMetadataSchema", () => {
  it.each([
    ["v1.0", validV1_0Metadata],
    ["v1.3", validV1_3Metadata],
    ["v1.4", validV1_4Metadata],
  ])("should accept valid %s metadata", (_label, metadata) => {
    expect(itWalletMetadataSchema.safeParse(metadata).success).toBe(true);
  });

  it("should accept valid APTITUDE metadata", () => {
    expect(
      isItWalletMetadataVersion(
        validAptitudeMetadata,
        ItWalletSpecsVersion.V1_4,
      ),
    ).toBe(false);
    expect(
      itWalletMetadataSchema.safeParse(validAptitudeMetadata).success,
    ).toBe(true);
  });
});

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
