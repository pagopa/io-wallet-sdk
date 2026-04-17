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

export interface VerifyWalletAttestationJwtOptionsV1_4
  extends BaseVerifyWalletAttestationJwtOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
}

export type VerifiedWalletAttestationJwtV1_4 = Awaited<
  ReturnType<typeof verifyWalletAttestationJwt>
>;

export async function verifyWalletAttestationJwt(
  options: VerifyWalletAttestationJwtOptionsV1_4,
) {
  return verifyWalletAttestationBase(
    options,
    zWalletAttestationJwtHeaderV1_4,
    zWalletAttestationJwtPayloadV1_4,
  );
}
