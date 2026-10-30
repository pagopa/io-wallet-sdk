import { describe, expect, it } from "vitest";

import { itWalletMetadataAPTITUDE } from "../../../itWalletMetadata";
import {
  aptitudeAuthorizationServerIdentifier,
  aptitudeAuthorizationServerMetadata,
} from "../aptitudeAuthorizationServer";

const validMetadata: Record<string, unknown> = {
  authorization_endpoint: "https://as.example.com/authorize",
  client_attestation_pop_methods_supported: ["dpop_combined"],
  client_attestation_signing_alg_values_supported: ["ES256"],
  dpop_signing_alg_values_supported: ["ES256"],
  issuer: "https://as.example.com",
  pushed_authorization_request_endpoint: "https://as.example.com/par",
  token_endpoint: "https://as.example.com/token",
  token_endpoint_auth_methods_supported: ["attest_jwt_client_auth_dpop"],
};

describe("aptitudeAuthorizationServerMetadata", () => {
  it("should expose the oauth_authorization_server identifier", () => {
    expect(aptitudeAuthorizationServerIdentifier).toBe(
      "oauth_authorization_server",
    );
  });

  it("should accept the RFC001 example", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse(validMetadata).success,
    ).toBe(true);
  });

  it("should preserve additional parameters", () => {
    const result = aptitudeAuthorizationServerMetadata.parse({
      ...validMetadata,
      jwks_uri: "https://as.example.com/jwks",
    });

    expect(result.jwks_uri).toBe("https://as.example.com/jwks");
  });

  it.each(Object.keys(validMetadata))(
    "should reject metadata missing %s",
    (field) => {
      const rest = Object.fromEntries(
        Object.entries(validMetadata).filter(([key]) => key !== field),
      );

      expect(aptitudeAuthorizationServerMetadata.safeParse(rest).success).toBe(
        false,
      );
    },
  );

  it("should reject token_endpoint_auth_methods_supported without attest_jwt_client_auth_dpop", () => {
    const result = aptitudeAuthorizationServerMetadata.safeParse({
      ...validMetadata,
      token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
    });

    expect(result.success).toBe(false);
  });

  it("should reject client_attestation_pop_methods_supported without dpop_combined", () => {
    const result = aptitudeAuthorizationServerMetadata.safeParse({
      ...validMetadata,
      client_attestation_pop_methods_supported: ["jwt"],
    });

    expect(result.success).toBe(false);
  });
});

describe("itWalletMetadataAPTITUDE", () => {
  it("should validate oauth_authorization_server against the APTITUDE schema", () => {
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: validMetadata,
      }).success,
    ).toBe(true);
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: {
          ...validMetadata,
          token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
        },
      }).success,
    ).toBe(false);
  });
});
