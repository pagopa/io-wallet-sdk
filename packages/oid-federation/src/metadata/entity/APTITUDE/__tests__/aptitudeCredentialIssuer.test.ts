import { describe, expect, it } from "vitest";

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
    "issuer_info",
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
