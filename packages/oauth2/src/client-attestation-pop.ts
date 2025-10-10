import {
  CallbackContext,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
  Jwk,
  JwtSignerJwk,
  decodeJwt,
  verifyJwt,
} from "@openid4vc/oauth2";
import {
  addSecondsToDate,
  dateToSeconds,
  encodeToBase64Url,
} from "@openid4vc/utils";

import { Oauth2Error } from "./errors";

export interface VerifyClientAttestationPopJwtOptions {
  /**
   * The issuer identifier of the authorization server handling the client attestation
   */
  authorizationServer: string;

  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;

  /**
   * The compact client attestation pop jwt.
   */
  clientAttestationPopJwt: string;

  clientAttestationPublicJwk: Jwk;

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string;

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date;
}

export type VerifiedClientAttestationPopJwt = Awaited<
  ReturnType<typeof verifyClientAttestationPopJwt>
>;
export async function verifyClientAttestationPopJwt(
  options: VerifyClientAttestationPopJwtOptions,
) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationPopJwt,
  });

  if (payload.aud !== options.authorizationServer) {
    throw new Oauth2Error(
      `Client Attestation Pop jwt contains 'aud' value '${payload.aud}', but expected authorization server identifier '${options.authorizationServer}'`,
    );
  }

  const { signer } = await verifyJwt({
    compact: options.clientAttestationPopJwt,
    errorMessage: "client attestation pop jwt verification failed",
    expectedNonce: options.expectedNonce,
    header,
    now: options.now,
    payload,
    signer: {
      alg: header.alg,
      method: "jwk",
      publicJwk: options.clientAttestationPublicJwk,
    },
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return {
    header,
    payload,
    signer,
  };
}

export interface CreateClientAttestationPopJwtOptions {
  /**
   * The audience authorization server identifier
   */
  authorizationServer: string;

  /**
   * Callback used for dpop
   */
  callbacks: Pick<CallbackContext, "generateRandom" | "signJwt">;

  /**
   * The client attestation to create the Pop for
   */
  clientAttestation: string;

  /**
   * Expiration time of the JWT. If not provided 1 minute will be added to the `issuedAt`
   */
  expiresAt?: Date;

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date;

  /**
   * The signer of jwt. Only jwk signer allowed.
   *
   * If not provided, the signer will be derived based on the
   * `cnf.jwk` and `alg` in the client attestation.
   */
  signer?: JwtSignerJwk;
}

export async function createClientAttestationPopJwt(
  options: CreateClientAttestationPopJwtOptions,
) {
  const clientAttestation = decodeJwt({
    jwt: options.clientAttestation,
  });

  const jwk = clientAttestation.payload.cnf?.jwk;
  if (!jwk) {
    throw new Oauth2Error(
      "Client attestation does not contain 'cnf.jwk', cannot create client attestation pop jwt",
    );
  }

  const signer = options.signer ?? {
    alg: clientAttestation.header.alg,
    method: "jwk",
    publicJwk: jwk,
  };

  const header = {
    alg: signer.alg,
    typ: "oauth-client-attestation-pop+jwt",
  } satisfies ClientAttestationPopJwtHeader;

  const expiresAt =
    options.expiresAt ??
    addSecondsToDate(options.issuedAt ?? new Date(), 1 * 60);

  const payload = {
    aud: options.authorizationServer,
    exp: dateToSeconds(expiresAt),
    iat: dateToSeconds(options.issuedAt ?? new Date()),
    iss: clientAttestation.payload.sub as string,
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
  } satisfies ClientAttestationPopJwtPayload;

  const { jwt } = await options.callbacks.signJwt(signer, {
    header,
    payload,
  });

  return jwt;
}
