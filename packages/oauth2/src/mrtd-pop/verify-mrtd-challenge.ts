import {
  CallbackContext,
  type JwtPayload,
  JwtSignerJwk,
  decodeJwt,
} from "@openid4vc/oauth2";

import { MrtdPopError } from "../errors";
import {
  MrtdChallengeJwtHeader,
  MrtdChallengeJwtPayload,
  zMrtdChallengeJwtHeader,
  zMrtdChallengeJwtPayload,
} from "./z-mrtd-pop";

export interface VerifyMrtdChallengeOptions {
  callbacks: Pick<CallbackContext, "verifyJwt">;
  challengeJwt: string;
  /** Expected client_id — must match JWT aud */
  clientId: string;
  signer: JwtSignerJwk;
}

export interface VerifyMrtdChallengeResult {
  header: MrtdChallengeJwtHeader;
  payload: MrtdChallengeJwtPayload;
}

/**
 * Verifies the MRTD challenge JWT signature and validates claims.
 *
 * Ensures the challenge was issued by the trusted PID Provider and is intended
 * for this Wallet Instance. Validates expiration, audience, and required parameters.
 *
 * @param options - Challenge JWT, expected client_id, and verification callback
 * @returns Verified header and payload
 * @throws {Error} If aud doesn't match clientId
 * @throws {Oauth2JwtVerificationError} If signature verification fails
 *
 * It is alligned to the IT-Wallet v1.3 specs
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.1 (MRTD Proof JWT)
 */
export async function verifyMrtdChallenge(
  options: VerifyMrtdChallengeOptions,
): Promise<VerifyMrtdChallengeResult> {
  const { callbacks, challengeJwt, clientId } = options;

  const jwt = decodeJwt({
    headerSchema: zMrtdChallengeJwtHeader,
    jwt: challengeJwt,
    payloadSchema: zMrtdChallengeJwtPayload,
  });

  if (jwt.payload.aud !== clientId) {
    throw new MrtdPopError(
      "Invalid challenge: aud claim does not match client_id",
    );
  }

  await callbacks.verifyJwt(options.signer, {
    compact: challengeJwt,
    header: jwt.header,
    // MRTD spec uses `status` as a string literal, but upstream JwtPayload types it as an object.
    // The cast is safe because verifyJwt only uses standard claims (exp, aud, iss, etc.).
    payload: jwt.payload as unknown as JwtPayload,
  });

  return { header: jwt.header, payload: jwt.payload };
}
