import z from "zod";

const zOpenidCredentialAuthorizationDetails = z.object({
  credential_configuration_id: z.string(),
  type: z.literal("openid_credential"),
});

const zItL2DocumentProofAuthorizationDetails = z.object({
  challenge_method: z.literal("mrtd+ias"),
  challenge_redirect_uri: z.string().url(),
  idphinting: z.string().url(),
  type: z.literal("it_l2+document_proof"),
});

export const zAuthorizationRequest = z
  .object({
    authorization_details: z
      .array(
        z.discriminatedUnion("type", [
          zOpenidCredentialAuthorizationDetails,
          zItL2DocumentProofAuthorizationDetails,
        ]),
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
    client_id: z
      .string()
      .describe(
        "MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.",
      ),
    pkceCodeVerifier: z
      .string()
      .describe(
        "Code verifier for PKCE. If not provided in CreatePushedAuthorizationRequestOptions, SDK will generate one.",
      ),
    request: z
      .string()
      .describe(
        "It MUST be a signed JWT. The private key corresponding to the public one in the cnf parameter inside the Wallet Attestation MUST be used for signing the Request Object.",
      ),
  })
  .passthrough();
export type PushedAuthorizationRequestSigned = z.infer<
  typeof zPushedAuthorizationRequestSigned
>;

export const zPushedAuthorizationRequestUnsigned = z
  .object({
    authorizationRequest: zAuthorizationRequest.describe(
      "The authorization request parameters as a plain object. " +
        "Used when require_signed_request_object is false.",
    ),
    client_id: z
      .string()
      .describe(
        "Thumbprint of the jwk value in the cnf parameter inside Wallet Attestation.",
      ),
    pkceCodeVerifier: z
      .string()
      .describe(
        "PKCE code verifier. Auto-generated if not provided in options.",
      ),
  })
  .passthrough();
export type PushedAuthorizationRequestUnsigned = z.infer<
  typeof zPushedAuthorizationRequestUnsigned
>;

/**
 * Union type for Pushed Authorization Request - can be either signed (JAR) or unsigned.
 * The variant depends on the Authorization Server's require_signed_request_object metadata.
 */
export type PushedAuthorizationRequest =
  | PushedAuthorizationRequestSigned
  | PushedAuthorizationRequestUnsigned;

export function isPushedAuthorizationRequestSigned(
  par: PushedAuthorizationRequest,
): par is PushedAuthorizationRequestSigned {
  return "request" in par && typeof par.request === "string";
}

export function isPushedAuthorizationRequestUnsigned(
  par: PushedAuthorizationRequest,
): par is PushedAuthorizationRequestUnsigned {
  return "authorizationRequest" in par;
}

export const zPushedAuthorizationResponse = z
  .object({
    expires_in: z.number().int(),
    request_uri: z.string(),
  })
  .passthrough();
export type PushedAuthorizationResponse = z.infer<
  typeof zPushedAuthorizationResponse
>;
