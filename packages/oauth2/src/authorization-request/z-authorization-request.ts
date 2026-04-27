import z from "zod";

import { MAX_JTI_LENGTH } from "../common/jwt/z-jwt";

const zOpenidCredentialAuthorizationDetails = z.object({
  credential_configuration_id: z.string(),
  type: z.literal("openid_credential"),
});

const zItL2DocumentProofAuthorizationDetails = z.object({
  challenge_method: z.literal("mrtd+ias"),
  challenge_redirect_uri: z.url(),
  idphinting: z.url(),
  type: z.literal("it_l2+document_proof"),
});

const zAuthorizationRequestBaseObject = z.looseObject({
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
  jti: z.string().max(MAX_JTI_LENGTH),
  redirect_uri: z.url(),
  response_type: z.string(),
  scope: z.string().optional(),
  state: z.string(),
});

const zAuthorizationRequestBase = zAuthorizationRequestBaseObject.refine(
  (data) =>
    data.authorization_details !== undefined || data.scope !== undefined,
  {
    message: "Either 'authorization_details' or 'scope' must be provided.",
    path: ["authorization_details"],
  },
);

export const zAuthorizationRequestV1_0 = zAuthorizationRequestBaseObject
  .extend({
    response_mode: z.string(),
  })
  .refine(
    (data) =>
      data.authorization_details !== undefined || data.scope !== undefined,
    {
      message: "Either 'authorization_details' or 'scope' must be provided.",
      path: ["authorization_details"],
    },
  );

export type AuthorizationRequestV1_0 = z.infer<
  typeof zAuthorizationRequestV1_0
>;

export const zAuthorizationRequestV1_3 = zAuthorizationRequestBase;
export type AuthorizationRequestV1_3 = z.infer<
  typeof zAuthorizationRequestV1_3
>;

export const zAuthorizationRequest = z.union([
  zAuthorizationRequestV1_0,
  zAuthorizationRequestV1_3,
]);
export type AuthorizationRequest = z.infer<typeof zAuthorizationRequest>;

export const zPushedAuthorizationRequestSigned = z.looseObject({
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
});

export type PushedAuthorizationRequestSigned = z.infer<
  typeof zPushedAuthorizationRequestSigned
>;

const zPushedAuthorizationRequestUnsignedBase = <
  TAuthorizationRequest extends z.ZodType,
>(
  authorizationRequest: TAuthorizationRequest,
) =>
  z.looseObject({
    authorizationRequest: authorizationRequest.describe(
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
  });

export const zPushedAuthorizationRequestUnsignedV1_0 =
  zPushedAuthorizationRequestUnsignedBase(zAuthorizationRequestV1_0);
export type PushedAuthorizationRequestUnsignedV1_0 = z.infer<
  typeof zPushedAuthorizationRequestUnsignedV1_0
>;

export const zPushedAuthorizationRequestUnsignedV1_3 =
  zPushedAuthorizationRequestUnsignedBase(zAuthorizationRequestV1_3);
export type PushedAuthorizationRequestUnsignedV1_3 = z.infer<
  typeof zPushedAuthorizationRequestUnsignedV1_3
>;

export const zPushedAuthorizationRequestUnsigned =
  zPushedAuthorizationRequestUnsignedBase(zAuthorizationRequest);
export type PushedAuthorizationRequestUnsigned =
  | PushedAuthorizationRequestUnsignedV1_0
  | PushedAuthorizationRequestUnsignedV1_3;

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

export const zPushedAuthorizationResponse = z.looseObject({
  expires_in: z.number().int(),
  request_uri: z.string(),
});
export type PushedAuthorizationResponse = z.infer<
  typeof zPushedAuthorizationResponse
>;
