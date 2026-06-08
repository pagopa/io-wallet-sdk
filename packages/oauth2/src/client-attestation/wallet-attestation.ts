import {
  FetchHeaders,
  ItWalletSpecsVersion,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";
import { zCompactJwt } from "@pagopa/io-wallet-utils";

import type {
  VerifiedWalletAttestationJwtV1_0,
  VerifyWalletAttestationJwtOptionsV1_0,
} from "./v1.0/verify-wallet-attestation-jwt";
import type {
  VerifiedWalletAttestationJwtV1_3,
  VerifyWalletAttestationJwtOptionsV1_3,
} from "./v1.3/verify-wallet-attestation-jwt";
import type {
  VerifiedWalletAttestationJwtV1_4,
  VerifyWalletAttestationJwtOptionsV1_4,
} from "./v1.4/verify-wallet-attestation-jwt";

import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./types";
import { verifyWalletAttestationJwt as verifyWalletAttestationJwtV1_0 } from "./v1.0/verify-wallet-attestation-jwt";
import { verifyWalletAttestationJwt as verifyWalletAttestationJwtV1_3 } from "./v1.3/verify-wallet-attestation-jwt";
import { verifyWalletAttestationJwt as verifyWalletAttestationJwtV1_4 } from "./v1.4/verify-wallet-attestation-jwt";

const dispatchVerifyWalletAttestationJwt = createVersionDispatcher<
  VerifyWalletAttestationJwtOptions,
  Promise<VerifiedWalletAttestationJwt>
>({
  [ItWalletSpecsVersion.V1_0]: (o) =>
    verifyWalletAttestationJwtV1_0(o as VerifyWalletAttestationJwtOptionsV1_0),
  [ItWalletSpecsVersion.V1_3]: (o) =>
    verifyWalletAttestationJwtV1_3(o as VerifyWalletAttestationJwtOptionsV1_3),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    verifyWalletAttestationJwtV1_4(o as VerifyWalletAttestationJwtOptionsV1_4),
});

export type VerifiedWalletAttestationJwt =
  | VerifiedWalletAttestationJwtV1_0
  | VerifiedWalletAttestationJwtV1_3
  | VerifiedWalletAttestationJwtV1_4;

export type VerifyWalletAttestationJwtOptions =
  | VerifyWalletAttestationJwtOptionsV1_0
  | VerifyWalletAttestationJwtOptionsV1_3
  | VerifyWalletAttestationJwtOptionsV1_4;

/**
 * Verifies a wallet/client attestation JWT according to the configured IT-Wallet version.
 *
 * @param options - Version-specific wallet attestation verification options.
 * @returns Decoded and verified wallet attestation data for the configured version.
 * @throws {ValidationError} If JWT header or payload validation fails.
 * @throws {Oauth2JwtParseError} If the attestation JWT cannot be decoded.
 * @throws {Oauth2JwtVerificationError} If signature verification fails.
 * @throws {ItWalletSpecsVersionError} If the configured version is unsupported.
 */
export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_0,
): Promise<VerifiedWalletAttestationJwtV1_0>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_3,
): Promise<VerifiedWalletAttestationJwtV1_3>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_4,
): Promise<VerifiedWalletAttestationJwtV1_4>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptions,
): Promise<VerifiedWalletAttestationJwt> {
  return dispatchVerifyWalletAttestationJwt(options);
}

/**
 * Extracts wallet attestation and PoP JWT header values from request headers.
 *
 * @param headers - Request headers to inspect.
 * @returns Parsed header values when both are present, `{ valid: true }` when neither is present,
 * or `{ valid: false }` when the pair is incomplete or malformed.
 */
export function extractClientAttestationJwtsFromHeaders(headers: FetchHeaders):
  | {
      clientAttestationPopHeader: string;
      valid: true;
      walletAttestationHeader: string;
    }
  | {
      clientAttestationPopHeader?: undefined;
      valid: true;
      walletAttestationHeader?: undefined;
    }
  | { valid: false } {
  const walletAttestationHeader = headers.get(oauthClientAttestationHeader);
  const clientAttestationPopHeader = headers.get(
    oauthClientAttestationPopHeader,
  );

  if (!walletAttestationHeader && !clientAttestationPopHeader) {
    return { valid: true };
  }

  if (!walletAttestationHeader || !clientAttestationPopHeader) {
    return { valid: false };
  }

  if (
    !zCompactJwt.safeParse(walletAttestationHeader).success ||
    !zCompactJwt.safeParse(clientAttestationPopHeader).success
  ) {
    return { valid: false };
  }

  return {
    clientAttestationPopHeader,
    valid: true,
    walletAttestationHeader,
  } as const;
}
