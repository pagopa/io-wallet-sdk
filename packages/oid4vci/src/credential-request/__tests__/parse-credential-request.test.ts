import { Oauth2JwtParseError } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { parseCredentialRequest } from "../parse-credential-request";

function createProofJwt(payload?: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
    }),
  ).toString("base64url");

  const jwtPayload = Buffer.from(
    JSON.stringify({
      aud: "https://issuer.example.com",
      iat: 1700000000,
      iss: "test-client-id",
      nonce: "test-nonce",
      ...payload,
    }),
  ).toString("base64url");

  return `${header}.${jwtPayload}.signature`;
}

describe("parseCredentialRequest", () => {
  it("parses and normalizes v1.0 credential request", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });
    const jwt = createProofJwt();

    const result = parseCredentialRequest({
      config,
      credentialRequest: {
        credential_identifier: "UniversityDegree",
        proof: {
          jwt,
          proof_type: "jwt",
        },
      },
    });

    expect(result.credential.credential_identifier).toBe("UniversityDegree");
    expect(result.proofs).toHaveLength(1);
    expect(result.proofs[0]).toEqual(
      expect.objectContaining({
        jwt,
        proofType: "jwt",
      }),
    );
  });

  it("parses and normalizes v1.3 credential request with multiple proofs", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    const result = parseCredentialRequest({
      config,
      credentialRequest: {
        credential_identifier: "education_degree",
        proofs: {
          jwt: [createProofJwt(), createProofJwt({ nonce: "test-nonce-2" })],
        },
      },
    });

    expect(result.proofs).toHaveLength(2);
    expect(result.proofs[0]?.payload.aud).toBe("https://issuer.example.com");
    expect(result.proofs[1]?.payload.nonce).toBe("test-nonce-2");
  });

  it("throws ValidationError when transaction_id is present in immediate flow", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    expect(() =>
      parseCredentialRequest({
        config,
        credentialRequest: {
          credential_identifier: "UniversityDegree",
          proof: {
            jwt: createProofJwt(),
            proof_type: "jwt",
          },
          transaction_id: "tx-1",
        },
      }),
    ).toThrow(ValidationError);
  });

  it("throws ValidationError when transaction_id is missing in deferred flow", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    expect(() =>
      parseCredentialRequest({
        config,
        credentialRequest: {
          credential_identifier: "education_degree",
          proofs: {
            jwt: [createProofJwt()],
          },
        },
        isDeferredFlow: true,
      }),
    ).toThrow(ValidationError);
  });

  it("throws ValidationError when iss is missing for authorization_code grant", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    expect(() =>
      parseCredentialRequest({
        config,
        credentialRequest: {
          credential_identifier: "UniversityDegree",
          proof: {
            jwt: createProofJwt({ iss: undefined }),
            proof_type: "jwt",
          },
        },
      }),
    ).toThrow(ValidationError);
  });

  it("allows missing iss for pre-authorized_code grant", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    });

    const result = parseCredentialRequest({
      config,
      credentialRequest: {
        credential_identifier: "education_degree",
        proofs: {
          jwt: [createProofJwt({ iss: undefined })],
        },
      },
      grantType: "pre-authorized_code",
    });

    expect(result.proofs[0]?.payload.iss).toBeUndefined();
  });

  it("throws ValidationError when expected audience does not match", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    expect(() =>
      parseCredentialRequest({
        config,
        credentialRequest: {
          credential_identifier: "UniversityDegree",
          proof: {
            jwt: createProofJwt(),
            proof_type: "jwt",
          },
        },
        expected: {
          audience: "https://wrong.example.com",
        },
      }),
    ).toThrow(ValidationError);
  });

  it("throws Oauth2JwtParseError when proof JWT is malformed", () => {
    const config = new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
    });

    expect(() =>
      parseCredentialRequest({
        config,
        credentialRequest: {
          credential_identifier: "UniversityDegree",
          proof: {
            jwt: "not-a-jwt",
            proof_type: "jwt",
          },
        },
      }),
    ).toThrow(Oauth2JwtParseError);
  });

  it("throws ItWalletSpecsVersionError for unsupported version", () => {
    const unsafeParse = parseCredentialRequest as unknown as (options: {
      config: { itWalletSpecsVersion: string };
      credentialRequest: Record<string, unknown>;
    }) => unknown;

    expect(() =>
      unsafeParse({
        config: { itWalletSpecsVersion: "9.9.9" },
        credentialRequest: {},
      }),
    ).toThrow(ItWalletSpecsVersionError);
  });
});
