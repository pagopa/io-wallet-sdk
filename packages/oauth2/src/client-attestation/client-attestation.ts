import {
  CallbackContext,
  JwtSigner,
  decodeJwt,
  jwtHeaderFromJwtSigner,
  jwtSignerFromJwt,
  verifyJwt,
  zCompactJwt,
} from "@openid4vc/oauth2";
import {
  FetchHeaders,
  dateToSeconds,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import {
  ClientAttestationJwtHeader,
  ClientAttestationJwtPayload,
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
  zClientAttestationJwtHeader,
  zClientAttestationJwtPayload,
} from "./z-client-attestation";

export type VerifiedClientAttestationJwt = Awaited<
  ReturnType<typeof verifyClientAttestationJwt>
>;

export interface VerifyClientAttestationJwtOptions {
  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;

  /**
   * The compact client attestation jwt.
   */
  clientAttestationJwt: string;

  /**
   * The current time to use when verifying the JWTs.
   * If not provided current time will be used.
   *
   * @default new Date()
   */
  now?: Date;
}

export async function verifyClientAttestationJwt(
  options: VerifyClientAttestationJwtOptions,
) {
  const { header, payload } = decodeJwt({
    headerSchema: zClientAttestationJwtHeader,
    jwt: options.clientAttestationJwt,
    payloadSchema: zClientAttestationJwtPayload,
  });

  const { signer } = await verifyJwt({
    compact: options.clientAttestationJwt,
    errorMessage: "client attestation jwt verification failed.",
    header,
    now: options.now,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return {
    header,
    payload,
    signer,
  };
}

export function extractClientAttestationJwtsFromHeaders(headers: FetchHeaders):
  | {
      clientAttestationHeader: string;
      clientAttestationPopHeader: string;
      valid: true;
    }
  | {
      clientAttestationHeader?: undefined;
      clientAttestationPopHeader?: undefined;
      valid: true;
    }
  | { valid: false } {
  const clientAttestationHeader = headers.get(oauthClientAttestationHeader);
  const clientAttestationPopHeader = headers.get(
    oauthClientAttestationPopHeader,
  );

  if (!clientAttestationHeader && !clientAttestationPopHeader) {
    return { valid: true };
  }

  if (!clientAttestationHeader || !clientAttestationPopHeader) {
    return { valid: false };
  }

  if (
    !zCompactJwt.safeParse(clientAttestationHeader).success ||
    !zCompactJwt.safeParse(clientAttestationPopHeader).success
  ) {
    return { valid: false };
  }

  return {
    clientAttestationHeader,
    clientAttestationPopHeader,
    valid: true,
  } as const;
}

export interface CreateClientAttestationJwtOptions {
  /**
   * Additional payload to include in the client attestation jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>;

  /**
   * It expresses the strength of the authentication mechanism backing the Wallet instance when interacting with a Relying Party.
   */
  authenticatorAssuranceLevel: ClientAttestationJwtPayload["aal"];

  /**
   * Callback used for client attestation
   */
  callbacks: Pick<CallbackContext, "signJwt">;

  /**
   * The client id of the client instance.
   */
  clientId: string;

  /**
   * The confirmation payload for the client, attesting the `jwk`, `key_type` and `user_authentication`
   */
  confirmation: ClientAttestationJwtPayload["cnf"];

  /**
   * Expiration time of the JWT.
   */
  expiresAt: Date;

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date;

  /**
   * Issuer of the client attestation, usually identifier of the client backend
   */
  issuer: string;

  /**
   * The signer of the client attestation jwt.
   */
  signer: JwtSigner;

  /**
   * Chain of trust for the client attestation jwt, containing the thumbprints of the jwk values in the cnf parameter inside Wallet Attestation, starting from the client and up to the root of trust.
   */
  trustChain: ClientAttestationJwtHeader["trust_chain"];
}

export async function createClientAttestationJwt(
  options: CreateClientAttestationJwtOptions,
) {
  const header = parseWithErrorHandling(zClientAttestationJwtHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    trust_chain: options.trustChain,
    typ: "oauth-client-attestation+jwt",
  } satisfies ClientAttestationJwtHeader);

  const payload = parseWithErrorHandling(zClientAttestationJwtPayload, {
    aal: options.authenticatorAssuranceLevel,
    cnf: options.confirmation,
    exp: dateToSeconds(options.expiresAt),
    iat: dateToSeconds(options.issuedAt),
    iss: options.issuer,
    sub: options.clientId,
    ...options.additionalPayload,
  } satisfies ClientAttestationJwtPayload);

  const { jwt } = await options.callbacks.signJwt(options.signer, {
    header,
    payload,
  });

  return jwt;
}
