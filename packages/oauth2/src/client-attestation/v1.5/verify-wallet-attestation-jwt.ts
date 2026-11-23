import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyWalletAttestationJwtOptions } from "../types";
import { verifyWalletAttestationBase } from "../verify-wallet-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_5,
  zWalletAttestationJwtPayloadV1_5,
} from "./z-wallet-attestation";

export interface VerifyWalletAttestationJwtOptionsV1_5 extends BaseVerifyWalletAttestationJwtOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_5>;
}

export type VerifiedWalletAttestationJwtV1_5 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

/**
 * Verifies an IT-Wallet v1.5 wallet attestation JWT.
 *
 * @param options - v1.5 verification options.
 * @returns Decoded and verified wallet attestation JWT data.
 * @throws {ValidationError} If the JWT header or payload does not satisfy the v1.5 schema.
 * @throws {JwtParseError} If the JWT cannot be decoded.
 * @throws {Oauth2JwtVerificationError} If signature verification fails.
 */
export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_5,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_5,
    zWalletAttestationJwtPayloadV1_5,
  );
}
