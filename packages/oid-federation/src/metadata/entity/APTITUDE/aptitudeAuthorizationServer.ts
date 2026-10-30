import { z } from "zod";

/**
 *
 * {@link https://aptitude-consortium.github.io/aptitude-eudi-wallet-specs/latest/RFCs/RFC001/#89-metadata-endpoints}
 *
 */
export const aptitudeAuthorizationServerMetadata = z.looseObject({
  authorization_endpoint: z.url(),
  client_attestation_pop_methods_supported: z
    .array(z.string())
    .refine((arr) => arr.includes("dpop_combined"), {
      message:
        "The client_attestation_pop_methods_supported array MUST include 'dpop_combined'.",
    }),
  client_attestation_signing_alg_values_supported: z.array(z.string()).min(1),
  dpop_signing_alg_values_supported: z.array(z.string()).min(1),
  issuer: z.url(),
  pushed_authorization_request_endpoint: z.url(),
  token_endpoint: z.url(),
  token_endpoint_auth_methods_supported: z
    .array(z.string())
    .refine((arr) => arr.includes("attest_jwt_client_auth_dpop"), {
      message:
        "The token_endpoint_auth_methods_supported array MUST include 'attest_jwt_client_auth_dpop'.",
    }),
});

export type AptitudeAuthorizationServerMetadata = z.input<
  typeof aptitudeAuthorizationServerMetadata
>;

export const aptitudeAuthorizationServerIdentifier =
  "oauth_authorization_server";
