import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyWalletAttestationJwtOptions } from "../types";
import { verifyWalletAttestationBase } from "../verify-wallet-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_3,
  zWalletAttestationJwtPayloadV1_3,
} from "./z-wallet-attestation";

export interface VerifyWalletAttestationJwtOptionsV1_3
  extends BaseVerifyWalletAttestationJwtOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3;
  } & IoWalletSdkConfig;
}

export type VerifiedWalletAttestationJwtV1_3 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_3,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_3,
    zWalletAttestationJwtPayloadV1_3,
  );
}
