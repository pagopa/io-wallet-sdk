import { zCompactJwt } from "@openid4vc/oauth2";
import {
  FetchHeaders,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import type {
  VerifiedWalletAttestationJwtV1_0,
  VerifyWalletAttestationJwtOptionsV1_0,
} from "./v1.0/verify-wallet-attestation-jwt";
import type {
  VerifiedWalletAttestationJwtV1_3,
  VerifyWalletAttestationJwtOptionsV1_3,
} from "./v1.3/verify-wallet-attestation-jwt";

import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./types";
import { verifyWalletAttestationJwt as verifyWalletAttestationJwtV1_0 } from "./v1.0/verify-wallet-attestation-jwt";
import { verifyWalletAttestationJwt as verifyWalletAttestationJwtV1_3 } from "./v1.3/verify-wallet-attestation-jwt";

function isV1_0Options(
  options: VerifyWalletAttestationJwtOptions,
): options is VerifyWalletAttestationJwtOptionsV1_0 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

function isV1_3Options(
  options: VerifyWalletAttestationJwtOptions,
): options is VerifyWalletAttestationJwtOptionsV1_3 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
}

export type VerifiedWalletAttestationJwt =
  | VerifiedWalletAttestationJwtV1_0
  | VerifiedWalletAttestationJwtV1_3;

export type VerifyWalletAttestationJwtOptions =
  | VerifyWalletAttestationJwtOptionsV1_0
  | VerifyWalletAttestationJwtOptionsV1_3;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_0,
): Promise<VerifiedWalletAttestationJwtV1_0>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_3,
): Promise<VerifiedWalletAttestationJwtV1_3>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptions,
): Promise<VerifiedWalletAttestationJwt> {
  const version = options.config.itWalletSpecsVersion;

  if (isV1_0Options(options)) {
    return verifyWalletAttestationJwtV1_0(options);
  }

  if (isV1_3Options(options)) {
    return verifyWalletAttestationJwtV1_3(options);
  }

  throw new ItWalletSpecsVersionError("verifyWalletAttestationJwt", version, [
    ItWalletSpecsVersion.V1_0,
    ItWalletSpecsVersion.V1_3,
  ]);
}

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
