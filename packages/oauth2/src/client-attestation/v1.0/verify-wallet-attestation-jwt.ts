import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyWalletAttestationJwtOptions } from "../types";
import { verifyWalletAttestationBase } from "../verify-wallet-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_0,
  zWalletAttestationJwtPayloadV1_0,
} from "./z-wallet-attestation";

export interface VerifyWalletAttestationJwtOptionsV1_0 extends BaseVerifyWalletAttestationJwtOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_0>;
}

export type VerifiedWalletAttestationJwtV1_0 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

/**
 * Verifies an IT-Wallet v1.0 wallet attestation JWT.
 *
 * @param options - v1.0 verification options.
 * @returns Decoded and verified wallet attestation JWT data.
 * @throws {ValidationError} If the JWT header or payload does not satisfy the v1.0 schema.
 * @throws {Oauth2JwtParseError} If the JWT cannot be decoded.
 * @throws {Oauth2JwtVerificationError} If signature verification fails.
 */
export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_0,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_0,
    zWalletAttestationJwtPayloadV1_0,
  );
}
