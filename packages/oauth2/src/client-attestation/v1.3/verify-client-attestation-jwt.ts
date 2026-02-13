import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyClientAttestationJwtOptions } from "../types";
import { verifyClientAttestationJwtBase } from "../verify-client-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_3,
  zWalletAttestationJwtPayloadV1_3,
} from "./z-wallet-attestation";

export interface VerifyClientAttestationJwtOptionsV1_3
  extends BaseVerifyClientAttestationJwtOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3;
  } & IoWalletSdkConfig;
}

export type VerifiedClientAttestationJwtV1_3 = Awaited<
  ReturnType<typeof verifyClientAttestationJwt>
>;

export async function verifyClientAttestationJwt(
  options: VerifyClientAttestationJwtOptionsV1_3,
) {
  return verifyClientAttestationJwtBase(
    options,
    zWalletAttestationJwtHeaderV1_3,
    zWalletAttestationJwtPayloadV1_3,
  );
}
