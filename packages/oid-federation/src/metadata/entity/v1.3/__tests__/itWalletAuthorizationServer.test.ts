import { describe, expect, it } from "vitest";

import { itWalletMetadataV1_3 } from "../../../itWalletMetadata";
import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata,
} from "../itWalletAuthorizationServer";

const validV1_3Metadata = {
  acr_values_supported: [
    "https://trust-anchor.eid-wallet.example.it/loa/low",
    "https://trust-anchor.eid-wallet.example.it/loa/substantial",
    "https://trust-anchor.eid-wallet.example.it/loa/high",
  ],
  authorization_endpoint: "https://auth.example.com/authorize",
  authorization_signing_alg_values_supported: ["ES256", "ES384"],
  client_attestation_pop_signing_alg_values_supported: ["ES256", "ES384"],
  client_attestation_signing_alg_values_supported: ["ES256", "ES384"],
  client_registration_types_supported: ["automatic"],
  code_challenge_methods_supported: ["S256"],
  dpop_signing_alg_values_supported: ["ES256"],
  grant_types_supported: ["authorization_code"],
  issuer: "https://auth.example.com",
  jwks: { keys: [] },
  pushed_authorization_request_endpoint: "https://auth.example.com/par",
  request_object_signing_alg_values_supported: ["ES256", "ES384"],
  require_signed_request_object: true,
  response_types_supported: ["code"],
  scopes_supported: ["openid"],
  token_endpoint: "https://auth.example.com/token",
  token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
  token_endpoint_auth_signing_alg_values_supported: ["ES256", "ES384"],
};

describe("itWalletAuthorizationServerMetadata v1.3 - valid metadata", () => {
  it("should validate v1.3.3 compliant metadata", () => {
    expect(() =>
      itWalletAuthorizationServerMetadata.parse(validV1_3Metadata),
    ).not.toThrow();
  });

  it("should validate with all three ACR levels", () => {
    const metadata = {
      ...validV1_3Metadata,
      acr_values_supported: [
        "https://trust-anchor.eid-wallet.example.it/loa/low",
        "https://trust-anchor.eid-wallet.example.it/loa/substantial",
        "https://trust-anchor.eid-wallet.example.it/loa/high",
      ],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadata),
    ).not.toThrow();
  });

  it("should validate with only one ACR level", () => {
    const metadata = {
      ...validV1_3Metadata,
      acr_values_supported: [
        "https://trust-anchor.eid-wallet.example.it/loa/high",
      ],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadata),
    ).not.toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - ACR values", () => {
  it("should reject v1.0 trust-registry ACR values", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      acr_values_supported: [
        "https://trust-registry.eid-wallet.example.it/loa/low",
      ],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should reject mixed v1.0 and v1.3 ACR values", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      acr_values_supported: [
        "https://trust-anchor.eid-wallet.example.it/loa/low",
        "https://trust-registry.eid-wallet.example.it/loa/substantial",
      ],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should require trust-anchor domain for all ACR values", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      acr_values_supported: ["https://custom-domain.example.it/loa/low"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - new mandatory fields", () => {
  it("should require client_attestation_signing_alg_values_supported", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { client_attestation_signing_alg_values_supported, ...metadata } =
      validV1_3Metadata;

    expect(() => itWalletAuthorizationServerMetadata.parse(metadata)).toThrow(
      /client_attestation_signing_alg_values_supported/,
    );
  });

  it("should require client_attestation_pop_signing_alg_values_supported", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { client_attestation_pop_signing_alg_values_supported, ...metadata } =
      validV1_3Metadata;

    expect(() => itWalletAuthorizationServerMetadata.parse(metadata)).toThrow(
      /client_attestation_pop_signing_alg_values_supported/,
    );
  });

  it("should require dpop_signing_alg_values_supported", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { dpop_signing_alg_values_supported, ...metadata } =
      validV1_3Metadata;

    expect(() => itWalletAuthorizationServerMetadata.parse(metadata)).toThrow(
      /dpop_signing_alg_values_supported/,
    );
  });

  it("should require require_signed_request_object", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { require_signed_request_object, ...metadata } = validV1_3Metadata;

    expect(() => itWalletAuthorizationServerMetadata.parse(metadata)).toThrow(
      /require_signed_request_object/,
    );
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - require_signed_request_object", () => {
  it("should require require_signed_request_object to be true", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      require_signed_request_object: false,
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should accept when require_signed_request_object is true", () => {
    const metadata = {
      ...validV1_3Metadata,
      require_signed_request_object: true,
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadata),
    ).not.toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - algorithm arrays", () => {
  it("should require at least one algorithm in client_attestation_signing_alg_values_supported", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      client_attestation_signing_alg_values_supported: [],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should require at least one algorithm in client_attestation_pop_signing_alg_values_supported", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      client_attestation_pop_signing_alg_values_supported: [],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should require at least one algorithm in dpop_signing_alg_values_supported", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      dpop_signing_alg_values_supported: [],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should accept multiple algorithms", () => {
    const metadata = {
      ...validV1_3Metadata,
      client_attestation_pop_signing_alg_values_supported: [
        "ES256",
        "ES384",
        "ES512",
      ],
      client_attestation_signing_alg_values_supported: [
        "ES256",
        "ES384",
        "ES512",
      ],
      dpop_signing_alg_values_supported: ["ES256", "ES384", "ES512"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadata),
    ).not.toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - passthrough", () => {
  it("should allow extra fields (passthrough)", () => {
    const metadataWithExtraFields = {
      ...validV1_3Metadata,
      another_field: 123,
      custom_field: "custom_value",
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadataWithExtraFields),
    ).not.toThrow();
  });

  it("should allow deprecated response_modes_supported field (passthrough)", () => {
    const metadataWithDeprecatedField = {
      ...validV1_3Metadata,
      response_modes_supported: ["query", "form_post.jwt"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(metadataWithDeprecatedField),
    ).not.toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - existing required fields", () => {
  it("should require code_challenge_methods_supported to include S256", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      code_challenge_methods_supported: ["plain"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow(/S256/);
  });

  it("should require grant_types_supported to include authorization_code", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      grant_types_supported: ["implicit"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow(/authorization_code/);
  });

  it("should require response_types_supported to include code", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      response_types_supported: ["token"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow(/code/);
  });

  it("should require token_endpoint_auth_methods_supported to include attest_jwt_client_auth", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow(/attest_jwt_client_auth/);
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - integration", () => {
  it("should be used in itWalletMetadataV1_3", () => {
    const metadata = {
      [itWalletAuthorizationServerIdentifier]: validV1_3Metadata,
    };

    expect(() => itWalletMetadataV1_3.parse(metadata)).not.toThrow();
  });

  it("should be optional in itWalletMetadataV1_3", () => {
    const metadata = {
      federation_entity: {
        contacts: ["info@example.com"],
        federation_resolve_endpoint: "https://example.com/resolve",
        organization_name: "Example Org",
      },
    };

    expect(() => itWalletMetadataV1_3.parse(metadata)).not.toThrow();
  });

  it("should reject v1.0 ACR values when used in itWalletMetadataV1_3", () => {
    const metadata = {
      [itWalletAuthorizationServerIdentifier]: {
        ...validV1_3Metadata,
        acr_values_supported: [
          "https://trust-registry.eid-wallet.example.it/loa/low",
        ],
      },
    };

    expect(() => itWalletMetadataV1_3.parse(metadata)).toThrow();
  });
});

describe("itWalletAuthorizationServerMetadata v1.3 - URL validation", () => {
  it("should require valid URLs for endpoint fields", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      authorization_endpoint: "not-a-url",
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });

  it("should require valid URL for issuer", () => {
    const invalidMetadata = {
      ...validV1_3Metadata,
      issuer: "invalid-issuer",
    };

    expect(() =>
      itWalletAuthorizationServerMetadata.parse(invalidMetadata),
    ).toThrow();
  });
});
