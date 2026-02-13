import { zCompactJwt } from "@openid4vc/oauth2";
import {
  FetchHeaders,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import * as V1_0 from "./v1.0";
import * as V1_3 from "./v1.3";
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./z-client-attestation";

function isV1_0Options(
  options: VerifyClientAttestationJwtOptions,
): options is V1_0.VerifyClientAttestationJwtOptionsV1_0 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

function isV1_3Options(
  options: VerifyClientAttestationJwtOptions,
): options is V1_3.VerifyClientAttestationJwtOptionsV1_3 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
}

export type VerifiedClientAttestationJwt =
  | V1_0.VerifiedClientAttestationJwtV1_0
  | V1_3.VerifiedClientAttestationJwtV1_3;

export type VerifyClientAttestationJwtOptions =
  | V1_0.VerifyClientAttestationJwtOptionsV1_0
  | V1_3.VerifyClientAttestationJwtOptionsV1_3;

export async function verifyClientAttestationJwt(
  options: V1_0.VerifyClientAttestationJwtOptionsV1_0,
): Promise<V1_0.VerifiedClientAttestationJwtV1_0>;

export async function verifyClientAttestationJwt(
  options: V1_3.VerifyClientAttestationJwtOptionsV1_3,
): Promise<V1_3.VerifiedClientAttestationJwtV1_3>;

export async function verifyClientAttestationJwt(
  options: VerifyClientAttestationJwtOptions,
): Promise<VerifiedClientAttestationJwt> {
  const version = options.config.itWalletSpecsVersion;

  if (isV1_0Options(options)) {
    return V1_0.verifyClientAttestationJwt(options);
  }

  if (isV1_3Options(options)) {
    return V1_3.verifyClientAttestationJwt(options);
  }

  throw new ItWalletSpecsVersionError("verifyClientAttestationJwt", version, [
    ItWalletSpecsVersion.V1_0,
    ItWalletSpecsVersion.V1_3,
  ]);
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
