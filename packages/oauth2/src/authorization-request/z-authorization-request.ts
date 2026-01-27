import z from "zod";

export const zAuthorizationRequest = z
  .object({
    authorization_details: z
      .array(
        z.object({
          credential_configuration_id: z.string(),
          type: z.literal("openid_credential"),
        }),
      )
      .optional(),
    client_id: z.string(),
    code_challenge: z.string(),
    code_challenge_method: z.string(),
    issuer_state: z.optional(z.string()),
    redirect_uri: z.string().url().optional(),
    response_mode: z.string(),
    response_type: z.string(),
    scope: z.string().optional(),
    state: z.string(),
  })
  .passthrough()
  .refine(
    (data) =>
      data.authorization_details !== undefined || data.scope !== undefined,
    {
      message: "Either 'authorization_details' or 'scope' must be provided.",
      path: ["authorization_details"],
    },
  );
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>;

export const zPushedAuthorizationRequestSigned = z
  .object({
    /*
     * MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.
     */
    client_id: z.string(),
    /**
     * Code verifier for PKCE. If not provided in CreatePushedAuthorizationRequestOptions, SDK will generate one.
     */
    pkceCodeVerifier: z.string(),

    /*
     * It MUST be a signed JWT. The private key corresponding to the public one in the cnf parameter inside the Wallet Attestation MUST be used for signing the Request Object.
     */
    request: z.string(),
  })
  .passthrough();
export type PushedAuthorizationRequestSigned = z.infer<
  typeof zPushedAuthorizationRequestSigned
>;

export const zPushedAuthorizationResponse = z
  .object({
    expires_in: z.number().int(),
    request_uri: z.string(),
  })
  .passthrough();
export type PushedAuthorizationResponse = z.infer<
  typeof zPushedAuthorizationResponse
>;
