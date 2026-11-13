import { describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";

import { itWalletMetadataAPTITUDE } from "../../../itWalletMetadata";
import {
  aptitudeCredentialIssuerIdentifier,
  aptitudeCredentialIssuerMetadata,
} from "../aptitudeCredentialIssuer";

const validMetadata: Record<string, unknown> = {
  authorization_servers: ["https://as.example.com"],
  credential_configurations_supported: {
    "eu.europa.ec.eudi.pid.1": {
      credential_signing_alg_values_supported: ["ES256"],
      format: "dc+sd-jwt",
      proof_types_supported: {
        attestation: { proof_signing_alg_values_supported: ["ES256"] },
        jwt: { proof_signing_alg_values_supported: ["ES256"] },
      },
      vct: "urn:eudi:pid:1",
    },
    "org.iso.18013.5.1.mDL": {
      credential_signing_alg_values_supported: [-7],
      doctype: "org.iso.18013.5.1.mDL",
      format: "mso_mdoc",
    },
  },
  credential_endpoint: "https://issuer.example.com/credential",
  credential_issuer: "https://issuer.example.com",
  deferred_credential_endpoint: "https://issuer.example.com/deferred",
  issuer_info: [
    { data: "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", format: "registration_cert" },
  ],
  nonce_endpoint: "https://issuer.example.com/nonce",
};

const withConfiguration = (configuration: unknown) => ({
  ...validMetadata,
  credential_configurations_supported: { cred: configuration },
});

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

describe("aptitudeCredentialIssuerMetadata", () => {
  it("should expose the openid_credential_issuer identifier", () => {
    expect(aptitudeCredentialIssuerIdentifier).toBe("openid_credential_issuer");
  });

  it("should accept the RFC001 example with SD-JWT VC and mdoc configurations", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(validMetadata).success,
    ).toBe(true);
  });

  it("should not require IT-Wallet specific parameters", () => {
    const result = aptitudeCredentialIssuerMetadata.safeParse(validMetadata);

    expect(result.success).toBe(true);
    expect(validMetadata).not.toHaveProperty("jwks");
    expect(validMetadata).not.toHaveProperty("trust_frameworks_supported");
  });

  it("should preserve additional parameters", () => {
    const result = aptitudeCredentialIssuerMetadata.parse({
      ...validMetadata,
      signed_metadata: "eyJ.e30.c2ln",
    });

    expect(result.signed_metadata).toBe("eyJ.e30.c2ln");
  });

  it.each([
    "credential_configurations_supported",
    "credential_endpoint",
    "credential_issuer",
    "nonce_endpoint",
  ])("should reject metadata missing %s", (field) => {
    const rest = Object.fromEntries(
      Object.entries(validMetadata).filter(([key]) => key !== field),
    );

    expect(aptitudeCredentialIssuerMetadata.safeParse(rest).success).toBe(
      false,
    );
  });

  it("should reject an empty issuer_info", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        issuer_info: [],
      }).success,
    ).toBe(false);
  });

  it("should accept an attestation-only proof_types_supported", () => {
    const result = aptitudeCredentialIssuerMetadata.safeParse(
      withConfiguration({
        format: "dc+sd-jwt",
        proof_types_supported: {
          attestation: { proof_signing_alg_values_supported: ["ES256"] },
        },
        vct: "urn:eudi:pid:1",
      }),
    );

    expect(result.success).toBe(true);
  });

  it("should reject a proof_types_supported with neither jwt nor attestation", () => {
    const result = aptitudeCredentialIssuerMetadata.safeParse(
      withConfiguration({
        format: "dc+sd-jwt",
        proof_types_supported: {},
        vct: "urn:eudi:pid:1",
      }),
    );

    expect(result.success).toBe(false);
  });

  it("should reject an SD-JWT VC configuration without vct", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(
        withConfiguration({ format: "dc+sd-jwt" }),
      ).success,
    ).toBe(false);
  });

  it("should reject an mdoc configuration without doctype", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(
        withConfiguration({ format: "mso_mdoc" }),
      ).success,
    ).toBe(false);
  });

  it("should reject an unsupported credential format", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(
        withConfiguration({ format: "jwt_vc_json" }),
      ).success,
    ).toBe(false);
  });
});

describe("aptitudeCredentialIssuerMetadata legacy configuration filtering", () => {
  const legacyConfiguration = {
    format: "vc+sd-jwt",
    vct: "urn:eudi:pid:1",
  };

  it("should remove legacy configurations while preserving supported configurations and extension fields", () => {
    const supportedConfigurations = {
      mdoc: {
        credential_signing_alg_values_supported: [-7],
        doctype: "org.iso.18013.5.1.mDL",
        format: "mso_mdoc",
      },
      sdJwt: {
        credential_signing_alg_values_supported: ["ES256"],
        custom_metadata: { enabled: true },
        format: "dc+sd-jwt",
        vct: "urn:eudi:pid:1",
      },
    };
    const configurations = {
      legacy: legacyConfiguration,
      ...supportedConfigurations,
    };

    const result = aptitudeCredentialIssuerMetadata.parse({
      ...validMetadata,
      credential_configurations_supported: configurations,
    });

    expect(result.credential_configurations_supported).toEqual(
      supportedConfigurations,
    );
    expect(configurations.legacy).toEqual(legacyConfiguration);

    type InputConfiguration = z.input<
      typeof aptitudeCredentialIssuerMetadata
    >["credential_configurations_supported"][string];
    type OutputConfiguration = z.output<
      typeof aptitudeCredentialIssuerMetadata
    >["credential_configurations_supported"][string];

    expectTypeOf<InputConfiguration["format"]>().toEqualTypeOf<
      "dc+sd-jwt" | "mso_mdoc" | "vc+sd-jwt"
    >();
    expectTypeOf<OutputConfiguration["format"]>().toEqualTypeOf<
      "dc+sd-jwt" | "mso_mdoc"
    >();
    expectTypeOf<
      Extract<OutputConfiguration, { format: "dc+sd-jwt" }>["vct"]
    >().toEqualTypeOf<string>();
    expectTypeOf<
      Extract<OutputConfiguration, { format: "mso_mdoc" }>["doctype"]
    >().toEqualTypeOf<string>();
  });

  it.each([
    ["only legacy configurations", { legacy: legacyConfiguration }],
    ["no configurations", {}],
  ])("should return an empty record for %s", (_label, configurations) => {
    const result = aptitudeCredentialIssuerMetadata.parse({
      ...validMetadata,
      credential_configurations_supported: configurations,
    });

    expect(result.credential_configurations_supported).toEqual({});
  });

  it.each([
    ["a missing vct", { format: "vc+sd-jwt" }],
    [
      "numeric signing algorithms",
      {
        ...legacyConfiguration,
        credential_signing_alg_values_supported: [-7],
      },
    ],
  ])(
    "should reject a legacy configuration with %s before filtering",
    (_label, configuration) => {
      expect(
        aptitudeCredentialIssuerMetadata.safeParse(
          withConfiguration(configuration),
        ).success,
      ).toBe(false);
    },
  );

  it("should filter legacy configurations through itWalletMetadataAPTITUDE", () => {
    const result = itWalletMetadataAPTITUDE.parse({
      [aptitudeCredentialIssuerIdentifier]:
        withConfiguration(legacyConfiguration),
    });

    expect(
      result[aptitudeCredentialIssuerIdentifier]
        ?.credential_configurations_supported,
    ).toEqual({});
  });
});

describe("aptitudeCredentialIssuerMetadata OpenID4VCI constraints", () => {
  it.each([1, 0, -1, 2.5])("should reject a batch_size of %s", (batchSize) => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        batch_credential_issuance: { batch_size: batchSize },
      }).success,
    ).toBe(false);
  });

  it("should accept a batch_size of 2", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        batch_credential_issuance: { batch_size: 2 },
      }).success,
    ).toBe(true);
  });

  it.each([
    [
      "SD-JWT VC credential_signing_alg_values_supported",
      {
        credential_signing_alg_values_supported: [],
        format: "dc+sd-jwt",
        vct: "urn:eudi:pid:1",
      },
    ],
    [
      "mdoc credential_signing_alg_values_supported",
      {
        credential_signing_alg_values_supported: [],
        doctype: "org.iso.18013.5.1.mDL",
        format: "mso_mdoc",
      },
    ],
    [
      "cryptographic_binding_methods_supported",
      {
        cryptographic_binding_methods_supported: [],
        format: "dc+sd-jwt",
        vct: "urn:eudi:pid:1",
      },
    ],
    [
      "key_storage",
      {
        format: "dc+sd-jwt",
        proof_types_supported: {
          jwt: {
            key_attestations_required: { key_storage: [] },
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "urn:eudi:pid:1",
      },
    ],
    [
      "user_authentication",
      {
        format: "dc+sd-jwt",
        proof_types_supported: {
          jwt: {
            key_attestations_required: { user_authentication: [] },
            proof_signing_alg_values_supported: ["ES256"],
          },
        },
        vct: "urn:eudi:pid:1",
      },
    ],
  ])("should reject an empty %s", (_label, configuration) => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(
        withConfiguration(configuration),
      ).success,
    ).toBe(false);
  });

  it("should accept non-empty optional arrays in a credential configuration", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse(
        withConfiguration({
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
          vct: "urn:eudi:pid:1",
        }),
      ).success,
    ).toBe(true);
  });
});

describe("aptitudeCredentialIssuerMetadata jwks", () => {
  it("should accept metadata without jwks", () => {
    const result = aptitudeCredentialIssuerMetadata.parse(validMetadata);

    expect(result.jwks).toBeUndefined();
  });

  it("should accept and preserve a valid jwks", () => {
    const result = aptitudeCredentialIssuerMetadata.parse({
      ...validMetadata,
      jwks: validJwks,
    });

    expect(result.jwks).toEqual(validJwks);
  });

  it("should accept an empty key set", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        jwks: { keys: [] },
      }).success,
    ).toBe(true);
  });

  it("should reject a jwks whose keys lack kid", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        jwks: { keys: [omit(validJwk, "kid")] },
      }).success,
    ).toBe(false);
  });

  it("should reject a jwks whose keys lack kty", () => {
    expect(
      aptitudeCredentialIssuerMetadata.safeParse({
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
      aptitudeCredentialIssuerMetadata.safeParse({
        ...validMetadata,
        jwks,
      }).success,
    ).toBe(false);
  });

  it("should validate jwks through itWalletMetadataAPTITUDE", () => {
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeCredentialIssuerIdentifier]: {
          ...validMetadata,
          jwks: validJwks,
        },
      }).success,
    ).toBe(true);
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeCredentialIssuerIdentifier]: {
          ...validMetadata,
          jwks: { keys: [{ kty: "EC" }] },
        },
      }).success,
    ).toBe(false);
  });
});

describe("itWalletMetadataAPTITUDE", () => {
  it("should validate openid_credential_issuer against the APTITUDE schema", () => {
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeCredentialIssuerIdentifier]: validMetadata,
      }).success,
    ).toBe(true);
    expect(
      itWalletMetadataAPTITUDE.safeParse({
        [aptitudeCredentialIssuerIdentifier]: {
          ...validMetadata,
          nonce_endpoint: undefined,
        },
      }).success,
    ).toBe(false);
  });
});
