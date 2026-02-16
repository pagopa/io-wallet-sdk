import { zCompactJwt } from "@openid4vc/oauth2";
import {
  FetchHeaders,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./types";
import * as V1_0 from "./v1.0";
import * as V1_3 from "./v1.3";

function isV1_0Options(
  options: VerifyWalletAttestationJwtOptions,
): options is V1_0.VerifyWalletAttestationJwtOptionsV1_0 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

function isV1_3Options(
  options: VerifyWalletAttestationJwtOptions,
): options is V1_3.VerifyWalletAttestationJwtOptionsV1_3 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
}

export type VerifiedWalletAttestationJwt =
  | V1_0.VerifiedWalletAttestationJwtV1_0
  | V1_3.VerifiedWalletAttestationJwtV1_3;

export type VerifyWalletAttestationJwtOptions =
  | V1_0.VerifyWalletAttestationJwtOptionsV1_0
  | V1_3.VerifyWalletAttestationJwtOptionsV1_3;

export async function verifyWalletAttestationJwt(
  options: V1_0.VerifyWalletAttestationJwtOptionsV1_0,
): Promise<V1_0.VerifiedWalletAttestationJwtV1_0>;

export async function verifyWalletAttestationJwt(
  options: V1_3.VerifyWalletAttestationJwtOptionsV1_3,
): Promise<V1_3.VerifiedWalletAttestationJwtV1_3>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptions,
): Promise<VerifiedWalletAttestationJwt> {
  const version = options.config.itWalletSpecsVersion;

  if (isV1_0Options(options)) {
    return V1_0.verifyWalletAttestationJwt(options);
  }

  if (isV1_3Options(options)) {
    return V1_3.verifyWalletAttestationJwt(options);
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
