import { addSecondsToDate, dateToSeconds, encodeToBase64Url } from '@openid4vc/utils'
import { CallbackContext, ClientAttestationPopJwtHeader, ClientAttestationPopJwtPayload, decodeJwt, Jwk, JwtSignerJwk, Oauth2Error, verifyJwt } from "@openid4vc/oauth2"

export interface VerifyClientAttestationPopJwtOptions {
  /**
   * The compact client attestation pop jwt.
   */
  clientAttestationPopJwt: string

  /**
   * The issuer identifier of the authorization server handling the client attestation
   */
  authorizationServer: string

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>

  clientAttestationPublicJwk: Jwk

}

export type VerifiedClientAttestationPopJwt = Awaited<ReturnType<typeof verifyClientAttestationPopJwt>>
export async function verifyClientAttestationPopJwt(options: VerifyClientAttestationPopJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationPopJwt
  })

  if (payload.aud !== options.authorizationServer) {
    throw new Oauth2Error(
      `Client Attestation Pop jwt contains 'aud' value '${payload.aud}', but expected authorization server identifier '${options.authorizationServer}'`
    )
  }

  const { signer } = await verifyJwt({
    signer: {
      alg: header.alg,
      method: 'jwk',
      publicJwk: options.clientAttestationPublicJwk,
    },
    now: options.now,
    header,
    expectedNonce: options.expectedNonce,
    payload,
    compact: options.clientAttestationPopJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'client attestation pop jwt verification failed',
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface CreateClientAttestationPopJwtOptions {

  /**
   * The audience authorization server identifier
   */
  authorizationServer: string

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * Expiration time of the JWT. If not proided 1 minute will be added to the `issuedAt`
   */
  expiresAt?: Date

  /**
   * The client attestation to create the Pop for
   */
  clientAttestation: string

  /**
   * Callback used for dpop
   */
  callbacks: Pick<CallbackContext, 'generateRandom' | 'signJwt'>

  /**
   * The signer of jwt. Only jwk signer allowed.
   *
   * If not provided, the signer will be derived based on the
   * `cnf.jwk` and `alg` in the client attestation.
   */
  signer?: JwtSignerJwk
}

export async function createClientAttestationPopJwt(options: CreateClientAttestationPopJwtOptions) {
  const clientAttestation = decodeJwt({
    jwt: options.clientAttestation
  })

  const signer = options.signer ?? {
    method: 'jwk',
    alg: clientAttestation.header.alg,
    publicJwk: clientAttestation.payload.cnf.jwk,
  }

  const header = {
    typ: 'oauth-client-attestation-pop+jwt',
    alg: signer.alg,
  } satisfies ClientAttestationPopJwtHeader;

  const expiresAt = options.expiresAt ?? addSecondsToDate(options.issuedAt ?? new Date(), 1 * 60)

  const payload = {
    aud: options.authorizationServer,
    iss: clientAttestation.payload.sub as string,
    iat: dateToSeconds(options.issuedAt),
    exp: dateToSeconds(expiresAt),
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
  } satisfies ClientAttestationPopJwtPayload;

  const { jwt } = await options.callbacks.signJwt(signer, {
    header,
    payload,
  })

  return jwt
}
