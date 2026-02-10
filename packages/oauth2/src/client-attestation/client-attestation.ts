import {
  CallbackContext,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
  zCompactJwt,
} from "@openid4vc/oauth2";
import { FetchHeaders } from "@pagopa/io-wallet-utils";

import {
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
