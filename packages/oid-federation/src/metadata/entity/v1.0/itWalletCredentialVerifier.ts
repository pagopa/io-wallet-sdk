import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/relying-party-metadata.html}
 *
 */
export const itWalletCredentialVerifierMetadata = z
  .object({
    application_type: z.literal("web"),
    authorization_encrypted_response_alg: z.string(),
    authorization_encrypted_response_enc: z.string(),
    authorization_signed_response_alg: z.string().refine((v) => v !== "none", {
      message: "The authorization_signed_response_alg MUST not be 'none'.",
    }),
    client_id: z.string().url(),
    client_name: z.string(),
    erasure_endpoint: z.string().url().optional(),
    jwks: jsonWebKeySetSchema,
    request_uris: z.array(z.string().url()),
    response_uris: z.array(z.string().url()),
    vp_formats: z.record(
      z.string(),
      z.object({
        alg: z.array(z.string()).optional(),
        "sd-jwt_alg_values": z.array(z.string()).optional(),
      }),
    ),
  })
  .passthrough();

export type ItWalletCredentialVerifierMetadata = z.input<
  typeof itWalletCredentialVerifierMetadata
>;

export const itWalletCredentialVerifierIdentifier =
  "openid_credential_verifier";
