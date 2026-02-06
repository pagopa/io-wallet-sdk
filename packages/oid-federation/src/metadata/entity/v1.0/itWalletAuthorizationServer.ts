import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/credential-issuer-solution.html#metadata-for-oauth-authorization-server}
 *
 */
export const itWalletAuthorizationServerMetadata = z
  .object({
    acr_values_supported: z.array(
      z.union([
        z.literal("https://trust-registry.eid-wallet.example.it/loa/low"),
        z.literal(
          "https://trust-registry.eid-wallet.example.it/loa/substantial",
        ),
        z.literal("https://trust-registry.eid-wallet.example.it/loa/high"),
      ]),
    ),
    authorization_endpoint: z.string().url(),
    authorization_signing_alg_values_supported: z.array(z.string()),
    client_registration_types_supported: z.array(
      z.union([z.literal("automatic"), z.literal("explicit")]),
    ),
    code_challenge_methods_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("S256"), {
        message:
          "The code_challenge_methods_supported array MUST include 'S256'.",
      }),
    grant_types_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("authorization_code"), {
        message:
          "The grant_types_supported array MUST include 'authorization_code'.",
      }),
    issuer: z.string().url(),
    jwks: jsonWebKeySetSchema,
    pushed_authorization_request_endpoint: z.string().url(),
    request_object_signing_alg_values_supported: z.array(z.string()),
    require_signed_request_object: z.boolean().optional(),
    response_modes_supported: z.array(
      z.union([z.literal("query"), z.literal("form_post.jwt")]),
    ),
    response_types_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("code"), {
        message: "The response_types_supported array MUST include 'code'.",
      }),
    scopes_supported: z.array(z.string()),
    token_endpoint: z.string().url(),
    token_endpoint_auth_methods_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("attest_jwt_client_auth"), {
        message:
          "The token_endpoint_auth_methods_supported array MUST include 'attest_jwt_client_auth'.",
      }),
    token_endpoint_auth_signing_alg_values_supported: z.array(z.string()),
  })
  .passthrough();

export type ItWalletAuthorizationServerMetadata = z.input<
  typeof itWalletAuthorizationServerMetadata
>;

export const itWalletAuthorizationServerIdentifier =
  "oauth_authorization_server";
