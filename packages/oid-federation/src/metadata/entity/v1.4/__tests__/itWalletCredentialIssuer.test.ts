import { describe, expect, it } from "vitest";

import {
  type ItWalletCredentialIssuerMetadata,
  itWalletCredentialIssuerMetadata,
} from "../itWalletCredentialIssuer";

const validMetadata: ItWalletCredentialIssuerMetadata = {
  authorization_servers: ["https://auth.example.com"],
  batch_credential_issuance: {
    batch_size: 10,
  },
  credential_configurations_supported: {
    UniversityDegree: {
      authentic_sources: {
        dataset_id: "university_degrees",
        entity_id: "https://university.example.com",
      },
      credential_metadata: {
        claims: [
          {
            display: [
              {
                description: "Full name of the degree holder",
                label: "Full Name",
                locale: "en-US",
              },
            ],
            mandatory: true,
            path: ["credentialSubject", "name"],
            sd: "never",
          },
        ],
        display: [
          {
            background_color: "#12107c",
            background_image: {
              uri: "https://issuer.example.org/bg.svg",
              "uri#integrity": "sha256-...",
            },
            description: "University degree credential",
            locale: "en-US",
            logo: {
              alt_text: "University logo",
              uri: "https://issuer.example.org/logo.svg",
              "uri#integrity": "sha256-...",
            },
            name: "University Degree",
            watermark_image: {
              uri: "https://issuer.example.org/watermark.svg",
              "uri#integrity": "sha256-...",
            },
          },
        ],
      },
      credential_signing_alg_values_supported: ["ES256"],
      cryptographic_binding_methods_supported: ["jwk"],
      format: "dc+sd-jwt",
      proof_types_supported: {
        jwt: {
          key_attestations_required: {
            key_storage: ["iso_18045_high"],
            user_authentication: ["iso_18045_high"],
          },
          proof_signing_alg_values_supported: ["ES256"],
        },
      },
      schema_id: "https://schema.example.org/UniversityDegree.json",
      scope: "UniversityDegree",
      vct: "UniversityDegree",
    },
  },
  credential_endpoint: "https://issuer.example.com/credential",
  credential_issuer: "https://issuer.example.com",
  deferred_credential_endpoint:
    "https://issuer.example.com/credential_deferred",
  display: [
    {
      locale: "en-US",
      name: "Example University",
    },
  ],
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "key-1",
        kty: "EC",
        x: "...",
        y: "...",
      },
    ],
  },
  nonce_endpoint: "https://issuer.example.com/nonce",
  notification_endpoint: "https://issuer.example.com/notification",
  status_list_aggregation_endpoint: "https://issuer.example.com/status-list",
  trust_frameworks_supported: ["it_wallet"],
};

describe("itWalletCredentialIssuerMetadata v1.4 metadata", () => {
  it("should validate complete v1.4 metadata with label field", () => {
    expect(() =>
      itWalletCredentialIssuerMetadata.parse(validMetadata),
    ).not.toThrow();
  });

  it("should validate metadata with optional fields omitted", () => {
    const minimalMetadata: ItWalletCredentialIssuerMetadata = {
      credential_configurations_supported: {
        SimpleCred: {
          authentic_sources: {
            dataset_id: "simple",
            entity_id: "https://simple.example.com",
          },
          credential_metadata: {
            display: [
              {
                locale: "en-US",
                name: "Simple Credential",
              },
            ],
          },
          credential_signing_alg_values_supported: ["ES256"],
          cryptographic_binding_methods_supported: ["jwk"],
          format: "dc+sd-jwt",
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ["ES256"],
            },
          },
          schema_id: "https://schema.example.org/Simple.json",
          scope: "SimpleCred",
          vct: "SimpleCred",
        },
      },
      credential_endpoint: "https://issuer.example.com/credential",
      credential_issuer: "https://issuer.example.com",
      jwks: {
        keys: [
          {
            crv: "P-256",
            kid: "key-1",
            kty: "EC",
            x: "...",
            y: "...",
          },
        ],
      },
      trust_frameworks_supported: ["it_wallet"],
    };

    expect(() =>
      itWalletCredentialIssuerMetadata.parse(minimalMetadata),
    ).not.toThrow();
  });

  it("should reject metadata missing required name in credential display", () => {
    const withoutName = {
      ...validMetadata,
      credential_configurations_supported: {
        TestCred: {
          ...validMetadata.credential_configurations_supported.UniversityDegree,
          credential_metadata: {
            display: [
              {
                locale: "en-US",
                // name is required and missing
              },
            ],
          },
        },
      },
    };

    expect(() =>
      itWalletCredentialIssuerMetadata.parse(withoutName),
    ).toThrow();
  });

  it("should reject name in ClaimDisplayMetadata (label is required in v1.4)", () => {
    const withClaimName = {
      ...validMetadata,
      credential_configurations_supported: {
        TestCred: {
          ...validMetadata.credential_configurations_supported.UniversityDegree,
          credential_metadata: {
            claims: [
              {
                display: [{ name: "Full Name", locale: "en-US" }],
                path: ["name"],
              },
            ],
          },
        },
      },
    };

    expect(() =>
      itWalletCredentialIssuerMetadata.parse(withClaimName),
    ).toThrow();
  });

  it("should validate mso_mdoc format credential", () => {
    const msoMdocMetadata = {
      ...validMetadata,
      credential_configurations_supported: {
        mDL: {
          authentic_sources: {
            dataset_id: "driving_licenses",
            entity_id: "https://dmv.example.gov",
          },
          credential_metadata: {
            display: [
              {
                locale: "en-US",
                name: "Mobile Driving License",
              },
            ],
          },
          credential_signing_alg_values_supported: [-7],
          cryptographic_binding_methods_supported: ["cose_key"],
          doctype: "org.iso.18013.5.1.mDL",
          format: "mso_mdoc",
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ["ES256"],
            },
          },
          schema_id: "https://schema.example.org/mDL.json",
          scope: "mDL",
        },
      },
    };

    expect(() =>
      itWalletCredentialIssuerMetadata.parse(msoMdocMetadata),
    ).not.toThrow();
  });
});
