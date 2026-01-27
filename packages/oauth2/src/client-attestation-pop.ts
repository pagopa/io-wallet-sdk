import {
  addSecondsToDate,
  dateToSeconds,
  encodeToBase64Url,
} from "@openid4vc/utils";
import { FetchHeaders } from "@pagopa/io-wallet-utils";
import z from "zod";

import { Oauth2Error } from "./errors";
import {
  CallbackContext,
  ClientAttestationPopJwtHeader,
  ClientAttestationPopJwtPayload,
  Jwk,
  JwtSignerJwk,
  decodeJwt,
  verifyJwt,
  zCompactJwt,
} from "./index";

export const zOauthClientAttestationHeader = z.literal(
  "OAuth-Client-Attestation",
);
export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value;
export const zOauthClientAttestationPopHeader = z.literal(
  "OAuth-Client-Attestation-PoP",
);
export const oauthClientAttestationPopHeader =
  zOauthClientAttestationPopHeader.value;

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

  /**
   * The public JWK to verify the client attestation pop jwt.
   */
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
  try {
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
  } catch (error) {
    if (error instanceof Oauth2Error) throw error;
    throw new Oauth2Error(
      `Error creating client attestation pop jwt : ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export interface CreateClientAttestationPopJwtOptions {
  /**
   * The audience authorization server identifier
   */
  authorizationServer: string;

  /**
   * Callback used for dpop
   * generateRandom is mandatory if jti is not provided
   */
  callbacks: Partial<Pick<CallbackContext, "generateRandom">> &
    Pick<CallbackContext, "signJwt">;

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
   * Optional jti to set in the payload. If not provided a random one will be generated
   */
  jti?: string;

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
  try {
    const clientAttestation = decodeJwt({
      jwt: options.clientAttestation,
    });

    const jwk = clientAttestation.payload.cnf?.jwk;
    if (!jwk) {
      throw new Oauth2Error(
        "Client attestation does not contain 'cnf.jwk', cannot create client attestation pop jwt",
      );
    }

    const sub = clientAttestation.payload.sub;
    if (!sub || typeof sub !== "string") {
      throw new Oauth2Error(
        "Client attestation does not contain 'sub', cannot create client attestation pop jwt",
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

    const issuedAt = options.issuedAt ?? new Date();
    const expiresAt = options.expiresAt ?? addSecondsToDate(issuedAt, 1 * 60);
    const jti =
      options.jti ??
      (options.callbacks.generateRandom
        ? encodeToBase64Url(await options.callbacks.generateRandom(32))
        : undefined);

    if (!jti) {
      throw new Oauth2Error(
        "Error: neither a default jti nor a generateRandom callback have been provided",
      );
    }

    const payload = {
      aud: options.authorizationServer,
      exp: dateToSeconds(expiresAt),
      iat: dateToSeconds(issuedAt),
      iss: sub,
      jti,
    } satisfies ClientAttestationPopJwtPayload;

    const { jwt } = await options.callbacks.signJwt(signer, {
      header,
      payload,
    });

    return jwt;
  } catch (error) {
    if (error instanceof Oauth2Error) throw error;
    throw new Oauth2Error(
      `Error creating client attestation pop jwt : ${error instanceof Error ? error.message : String(error)}`,
    );
  }
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
    return { valid: false } as const;
  }

  return {
    clientAttestationHeader,
    clientAttestationPopHeader,
    valid: true,
  } as const;
}
