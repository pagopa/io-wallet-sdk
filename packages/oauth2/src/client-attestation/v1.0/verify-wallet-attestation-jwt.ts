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

export interface VerifyWalletAttestationJwtOptionsV1_0
  extends BaseVerifyWalletAttestationJwtOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0;
  } & IoWalletSdkConfig;
}

export type VerifiedWalletAttestationJwtV1_0 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_0,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_0,
    zWalletAttestationJwtPayloadV1_0,
  );
}
