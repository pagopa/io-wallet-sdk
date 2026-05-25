import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyWalletAttestationJwtOptions } from "../types";
import { verifyWalletAttestationBase } from "../verify-wallet-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_4,
  zWalletAttestationJwtPayloadV1_4,
} from "./z-wallet-attestation";

export interface VerifyWalletAttestationJwtOptionsV1_4 extends BaseVerifyWalletAttestationJwtOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
}

export type VerifiedWalletAttestationJwtV1_4 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

/**
 * Verifies an IT-Wallet v1.4 wallet attestation JWT.
 *
 * @param options - v1.4 verification options.
 * @returns Decoded and verified wallet attestation JWT data.
 * @throws {ValidationError} If the JWT header or payload does not satisfy the v1.4 schema.
 * @throws {Oauth2JwtParseError} If the JWT cannot be decoded.
 * @throws {Oauth2JwtVerificationError} If signature verification fails.
 */
export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_4,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_4,
    zWalletAttestationJwtPayloadV1_4,
  );
}
