import { z } from "zod";

import { zFederationJwkSet } from "../../../jwk/z-federation-jwk";

// RFC 8414 §2: when grant_types_supported is omitted, the default value is
// ["authorization_code", "implicit"].
const defaultGrantTypesSupported = ["authorization_code", "implicit"];

const authorizationCodeFlowEndpoints = [
  "authorization_endpoint",
  "pushed_authorization_request_endpoint",
] as const;

/**
 *
 * {@link https://aptitude-consortium.github.io/aptitude-eudi-wallet-specs/latest/RFCs/RFC001/#89-metadata-endpoints}
 *
 * TODO [WLS-189] : RFC001 §8.9 lists the authorisation and PAR endpoints unconditionally, but
 * §7.3 scopes them to the Authorisation Code Flow and Issuers may support only
 * the Pre-Authorised Code Flow (§7.2). They are therefore required only when
 * the Authorization Server supports the authorization_code grant.
 *
 */
export const aptitudeAuthorizationServerMetadata = z
  .looseObject({
    authorization_endpoint: z.url().optional(),
    client_attestation_pop_methods_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("dpop_combined"), {
        message:
          "The client_attestation_pop_methods_supported array MUST include 'dpop_combined'.",
      }),
    client_attestation_signing_alg_values_supported: z.array(z.string()).min(1),
    dpop_signing_alg_values_supported: z.array(z.string()).min(1),
    grant_types_supported: z.array(z.string()).optional(),
    issuer: z.url(),
    // TODO [WLS-185] : This option has been added only for temporary compatibility with ITW
    // When the APTITUDE trust model will be effectively implemented and signing keys will
    // be retrieved and verified via the LoTE + x5c mechanism this can be removed
    jwks: zFederationJwkSet.optional(),
    pushed_authorization_request_endpoint: z.url().optional(),
    token_endpoint: z.url(),
    token_endpoint_auth_methods_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("attest_jwt_client_auth_dpop"), {
        message:
          "The token_endpoint_auth_methods_supported array MUST include 'attest_jwt_client_auth_dpop'.",
      }),
  })
  .superRefine((metadata, ctx) => {
    const grantTypesSupported =
      metadata.grant_types_supported ?? defaultGrantTypesSupported;

    if (!grantTypesSupported.includes("authorization_code")) {
      return;
    }

    for (const endpoint of authorizationCodeFlowEndpoints) {
      if (metadata[endpoint] === undefined) {
        ctx.addIssue({
          code: "custom",
          message: `The ${endpoint} parameter MUST be present when the authorization_code grant is supported.`,
          path: [endpoint],
        });
      }
    }
  });

export type AptitudeAuthorizationServerMetadata = z.input<
  typeof aptitudeAuthorizationServerMetadata
>;

export const aptitudeAuthorizationServerIdentifier =
  "oauth_authorization_server";
