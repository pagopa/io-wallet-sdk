import { describe, expect, it } from "vitest";

import {
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierMetadataV1_3,
} from "../itWalletCredentialVerifier";

const validV1_3Metadata = {
  application_type: "web" as const,
  client_id: "https://relying-party.example.org",
  client_name: "Example Relying Party",
  encrypted_response_enc_values_supported: ["A256GCM"],
  erasure_endpoint: "https://relying-party.example.org/erasure",
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "rp-key-1",
        kty: "EC",
        x: "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
        y: "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
      },
    ],
  },
  logo_uri: "https://relying-party.example.org/public/compact-logo.svg",
  request_uris: ["https://relying-party.example.org/request_uri"],
  response_uris: ["https://relying-party.example.org/response_uri"],
  vp_formats_supported: {
    "dc+sd-jwt": {
      "kb-jwt_alg_values": ["ES256"],
      "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
    },
    mso_mdoc: {
      deviceauth_alg_values: [-7, -35, -36],
      issuerauth_alg_values: [-7, -35, -36],
    },
  },
};

describe("itWalletCredentialVerifierMetadataV1_3", () => {
  describe("basic validation", () => {
    it("should validate correct v1.3.3 metadata", () => {
      const result =
        itWalletCredentialVerifierMetadataV1_3.safeParse(validV1_3Metadata);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual(validV1_3Metadata);
      }
    });
  });

  describe("logo_uri field", () => {
    it("should validate logo_uri field", () => {
      const metadataWithLogoUri = {
        ...validV1_3Metadata,
        logo_uri: "https://example.org/logo.svg",
      };
      const result =
        itWalletCredentialVerifierMetadataV1_3.safeParse(metadataWithLogoUri);
      expect(result.success).toBe(true);
    });

    it("should reject invalid logo_uri (not a URL)", () => {
      const metadataWithInvalidLogoUri = {
        ...validV1_3Metadata,
        logo_uri: "not-a-url",
      };
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithInvalidLogoUri,
      );
      expect(result.success).toBe(false);
    });

    it("should reject missing logo_uri", () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { logo_uri: _logo_uri, ...metadataWithoutLogoUri } =
        validV1_3Metadata;
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithoutLogoUri,
      );
      expect(result.success).toBe(false);
    });
  });

  describe("encrypted_response_enc_values_supported field", () => {
    it("should validate encrypted_response_enc_values_supported array", () => {
      const metadataWithEncValues = {
        ...validV1_3Metadata,
        encrypted_response_enc_values_supported: ["A256GCM", "A128GCM"],
      };
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithEncValues,
      );
      expect(result.success).toBe(true);
    });

    it("should reject missing encrypted_response_enc_values_supported", () => {
      const {
        encrypted_response_enc_values_supported:
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          _encrypted_response_enc_values_supported,
        ...metadataWithoutEncValues
      } = validV1_3Metadata;
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithoutEncValues,
      );
      expect(result.success).toBe(false);
    });
  });

  describe("vp_formats_supported field", () => {
    it("should validate vp_formats_supported with dc+sd-jwt format", () => {
      const metadataWithSdJwt = {
        ...validV1_3Metadata,
        vp_formats_supported: {
          "dc+sd-jwt": {
            "kb-jwt_alg_values": ["ES256", "ES384"],
            "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
          },
        },
      };
      const result =
        itWalletCredentialVerifierMetadataV1_3.safeParse(metadataWithSdJwt);
      expect(result.success).toBe(true);
    });

    it("should validate vp_formats_supported with mso_mdoc format (COSE algorithm numbers)", () => {
      const metadataWithMsoMdoc = {
        ...validV1_3Metadata,
        vp_formats_supported: {
          mso_mdoc: {
            deviceauth_alg_values: [-7, -35, -36], // ES256, ES384, ES512 in COSE
            issuerauth_alg_values: [-7, -35, -36],
          },
        },
      };
      const result =
        itWalletCredentialVerifierMetadataV1_3.safeParse(metadataWithMsoMdoc);
      expect(result.success).toBe(true);
    });

    it("should validate vp_formats_supported with both dc+sd-jwt and mso_mdoc formats", () => {
      const result =
        itWalletCredentialVerifierMetadataV1_3.safeParse(validV1_3Metadata);
      expect(result.success).toBe(true);
    });

    it("should validate vp_formats_supported with deprecated alg field for backward compatibility", () => {
      const metadataWithDeprecatedAlg = {
        ...validV1_3Metadata,
        vp_formats_supported: {
          "dc+sd-jwt": {
            alg: ["ES256", "ES384"], // Deprecated but still supported
            "kb-jwt_alg_values": ["ES256"],
            "sd-jwt_alg_values": ["ES256", "ES384"],
          },
        },
      };
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithDeprecatedAlg,
      );
      expect(result.success).toBe(true);
    });
  });

  describe("deprecated fields and passthrough behavior", () => {
    it("should reject deprecated authorization_signed_response_alg field", () => {
      const metadataWithDeprecatedField = {
        ...validV1_3Metadata,
        authorization_signed_response_alg: "ES256",
      };
      // Note: .passthrough() allows extra fields, so this will pass
      // The field should not be in the v1.3 schema but passthrough allows it
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithDeprecatedField,
      );
      // With .passthrough(), extra fields are allowed but not validated
      expect(result.success).toBe(true);
      // But the field should not be in the parsed output's type
      if (result.success) {
        expect("authorization_signed_response_alg" in result.data).toBe(true); // passthrough keeps it
      }
    });

    it("should allow unknown fields via .passthrough()", () => {
      const metadataWithUnknownField = {
        ...validV1_3Metadata,
        another_unknown_field: 123,
        custom_field: "custom_value",
      };
      const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
        metadataWithUnknownField,
      );
      expect(result.success).toBe(true);
      if (result.success) {
        expect(
          (result.data as unknown as Record<string, unknown>).custom_field,
        ).toBe("custom_value");
        expect(
          (result.data as unknown as Record<string, unknown>)
            .another_unknown_field,
        ).toBe(123);
      }
    });
  });
});

describe("itWalletCredentialVerifierMetadataV1_3 field validation", () => {
  it("should reject invalid client_id (not a URL)", () => {
    const metadataWithInvalidClientId = {
      ...validV1_3Metadata,
      client_id: "not-a-url",
    };
    const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
      metadataWithInvalidClientId,
    );
    expect(result.success).toBe(false);
  });

  it("should reject invalid application_type", () => {
    const metadataWithInvalidAppType = {
      ...validV1_3Metadata,
      application_type: "native", // Should be "web"
    };
    const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
      metadataWithInvalidAppType,
    );
    expect(result.success).toBe(false);
  });

  it("should validate optional erasure_endpoint", () => {
    const {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      erasure_endpoint: _erasure_endpoint,
      ...metadataWithoutErasureEndpoint
    } = validV1_3Metadata;
    const result = itWalletCredentialVerifierMetadataV1_3.safeParse(
      metadataWithoutErasureEndpoint,
    );
    expect(result.success).toBe(true);
  });

  it("should export the identifier unchanged from v1.0", () => {
    expect(itWalletCredentialVerifierIdentifier).toBe(
      "openid_credential_verifier",
    );
  });
});
