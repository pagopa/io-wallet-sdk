import { z } from "zod";
import { JWKS } from "../../jwk";

export const itWalletCredentialVerifierMetadata = z.object({
  client_id: z.string().url(),
  client_name: z.string(),
  application_type: z.literal("web"),
  request_uris: z.array(z.string().url()),
  response_uris: z.array(z.string().url()),
  authorization_signed_response_alg: z.string().refine((v) => v === "none", {
    message: "The authorization_signed_response_alg MUST not be 'none'.",
  }),
  authorization_encrypted_response_alg: z.string(),
  authorization_encrypted_response_enc: z.string(),
  vp_formats: z.record(
    z.string(),
    z.object({
      "sd-jwt_alg_values": z.array(z.string()).optional(),
      alg: z.array(z.string()).optional(),
    }),
  ),
  jwks: JWKS,
  erasure_endpoint: z.string().url().optional(),
});

export type ItWalletCredentialVerifierMetadata = z.input<
  typeof itWalletCredentialVerifierMetadata
>;

export const itWalletCredentialVerifierIdentifier =
  "openid_credential_verifier";
