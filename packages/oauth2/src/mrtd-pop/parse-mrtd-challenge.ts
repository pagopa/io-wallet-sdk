import { decodeJwt, zCompactJwt } from "@openid4vc/oauth2";

import { MrtdPopError } from "../errors";
import {
  MrtdChallengeJwtHeader,
  MrtdChallengeJwtPayload,
  zMrtdChallengeJwtHeader,
  zMrtdChallengeJwtPayload,
} from "./z-mrtd-pop";

export interface ParseMrtdChallengeOptions {
  /** The full redirect URL containing ?challenge_info=<jwt> */
  redirectUrl: string;
}

export interface ParseMrtdChallengeResult {
  challengeJwt: string;
  header: MrtdChallengeJwtHeader;
  payload: MrtdChallengeJwtPayload;
}

/**
 * Extracts and decodes the MRTD challenge JWT from authorization redirect (Phase 3.1 of L2+ flow).
 *
 * After primary authentication (LoA3), the Authorization Server redirects to the Wallet
 * with a JWT containing challenge requirements for document validation.
 *
 * @param options - Redirect URL containing challenge_info query parameter
 * @returns Decoded JWT header and payload (signature not yet verified)
 * @throws {MrtdPopError} If challenge_info is missing or JWT format is invalid
 *
 * It is alligned to the IT-Wallet v1.3 specs
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.1 (MRTD Proof JWT)
 */
export function parseMrtdChallenge(
  options: ParseMrtdChallengeOptions,
): ParseMrtdChallengeResult {
  const url = new URL(options.redirectUrl);
  const challengeJwt = url.searchParams.get("challenge_info");

  if (!challengeJwt) {
    throw new MrtdPopError(
      "Missing 'challenge_info' query parameter in redirect URL",
    );
  }

  if (!zCompactJwt.safeParse(challengeJwt).success) {
    throw new MrtdPopError(
      "Invalid JWT format in 'challenge_info' query parameter",
    );
  }

  const { header, payload } = decodeJwt({
    headerSchema: zMrtdChallengeJwtHeader,
    jwt: challengeJwt,
    payloadSchema: zMrtdChallengeJwtPayload,
  });

  return { challengeJwt, header, payload };
}
