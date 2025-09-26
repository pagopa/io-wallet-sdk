import z from "zod";

export const zAuthorizationRequest = z
  .object({
    response_type: z.string(),
    response_mode: z.string(),
    client_id: z.string(),
    state: z.string(),
    code_challenge: z.string(),
    code_challenge_method: z.string(),
    scope: z.string(),
    authorization_details: z.array(
      z.object({
        type: z.literal("openid_credential"),
        credential_configuration_id: z.string(),
      }),
    ),
    redirect_uri: z.string().url().optional(),
    issuer_state: z.optional(z.string()),
  })
  .passthrough();
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>;

export const zPushedAuthorizationRequestSigned = z
  .object({
    /*
     * It MUST be a signed JWT. The private key corresponding to the public one in the cnf parameter inside the Wallet Attestation MUST be used for signing the Request Object.
     */
    request: z.string(),
    /*
     * MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.
     */
    client_id: z.string(),
  })
  .passthrough();
export type PushedAuthorizationRequestSigned = z.infer<
  typeof zPushedAuthorizationRequestSigned
>;

export const zPushedAuthorizationResponse = z
  .object({
    request_uri: z.string(),
    expires_in: z.number().int(),
  })
  .passthrough();
export type PushedAuthorizationResponse = z.infer<
  typeof zPushedAuthorizationResponse
>;
