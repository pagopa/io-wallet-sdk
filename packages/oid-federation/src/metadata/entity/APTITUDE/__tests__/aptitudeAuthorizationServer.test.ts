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

const validJwk = {
  crv: "P-256",
  kid: "signing-key-1",
  kty: "EC",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
};

const validJwks = { keys: [validJwk] };

const omit = (object: Record<string, unknown>, field: string) =>
  Object.fromEntries(Object.entries(object).filter(([key]) => key !== field));

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

const preAuthorizedCodeGrant =
  "urn:ietf:params:oauth:grant-type:pre-authorized_code";

const authorizationCodeFlowEndpoints = [
  "authorization_endpoint",
  "pushed_authorization_request_endpoint",
];

describe("aptitudeAuthorizationServerMetadata authorization code flow endpoints", () => {
  it.each(authorizationCodeFlowEndpoints)(
    "should require %s when grant_types_supported includes authorization_code",
    (field) => {
      const result = aptitudeAuthorizationServerMetadata.safeParse({
        ...omit(validMetadata, field),
        grant_types_supported: ["authorization_code", preAuthorizedCodeGrant],
      });

      expect(result.success).toBe(false);
      expect(result.error?.issues[0]?.path).toEqual([field]);
    },
  );

  it.each(authorizationCodeFlowEndpoints)(
    "should require %s when grant_types_supported is omitted (RFC 8414 default)",
    (field) => {
      const result = aptitudeAuthorizationServerMetadata.safeParse(
        omit(validMetadata, field),
      );

      expect(result.success).toBe(false);
      expect(result.error?.issues[0]?.path).toEqual([field]);
    },
  );

  it("should not require the endpoints when only the pre-authorized code grant is supported", () => {
    const metadata = authorizationCodeFlowEndpoints.reduce(omit, {
      ...validMetadata,
      grant_types_supported: [preAuthorizedCodeGrant],
    });

    expect(
      aptitudeAuthorizationServerMetadata.safeParse(metadata).success,
    ).toBe(true);
  });

  it("should accept the endpoints when only the pre-authorized code grant is supported", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        grant_types_supported: [preAuthorizedCodeGrant],
      }).success,
    ).toBe(true);
  });

  it("should still validate the endpoints as URLs when present", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        grant_types_supported: [preAuthorizedCodeGrant],
        pushed_authorization_request_endpoint: "not-a-url",
      }).success,
    ).toBe(false);
  });

  it("should validate the conditional endpoints through itWalletMetadataAPTITUDE", () => {
    const preAuthorizedOnly = authorizationCodeFlowEndpoints.reduce(omit, {
      ...validMetadata,
      grant_types_supported: [preAuthorizedCodeGrant],
    });

    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: preAuthorizedOnly,
      }).success,
    ).toBe(true);
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: {
          ...preAuthorizedOnly,
          grant_types_supported: ["authorization_code"],
        },
      }).success,
    ).toBe(false);
  });
});

describe("aptitudeAuthorizationServerMetadata jwks", () => {
  it("should accept metadata without jwks", () => {
    const result = aptitudeAuthorizationServerMetadata.parse(validMetadata);

    expect(result.jwks).toBeUndefined();
  });

  it("should accept and preserve a valid jwks", () => {
    const result = aptitudeAuthorizationServerMetadata.parse({
      ...validMetadata,
      jwks: validJwks,
    });

    expect(result.jwks).toEqual(validJwks);
  });

  it("should accept an empty key set", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        jwks: { keys: [] },
      }).success,
    ).toBe(true);
  });

  it("should reject a jwks whose keys lack kid", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        jwks: { keys: [omit(validJwk, "kid")] },
      }).success,
    ).toBe(false);
  });

  it("should reject a jwks whose keys lack kty", () => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        jwks: { keys: [omit(validJwk, "kty")] },
      }).success,
    ).toBe(false);
  });

  it.each([
    ["a jwks without keys", {}],
    ["a jwks with non-array keys", { keys: validJwk }],
    ["a jwks given as a URL", "https://example.com/jwks"],
  ])("should reject %s", (_label, jwks) => {
    expect(
      aptitudeAuthorizationServerMetadata.safeParse({
        ...validMetadata,
        jwks,
      }).success,
    ).toBe(false);
  });

  it("should validate jwks through itWalletMetadataAPTITUDE", () => {
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: {
          ...validMetadata,
          jwks: validJwks,
        },
      }).success,
    ).toBe(true);
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeAuthorizationServerIdentifier]: {
          ...validMetadata,
          jwks: { keys: [{ kty: "EC" }] },
        },
      }).success,
    ).toBe(false);
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
