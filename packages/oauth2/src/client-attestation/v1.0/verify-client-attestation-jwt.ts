import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseVerifyClientAttestationJwtOptions } from "../types";
import { verifyClientAttestationJwtBase } from "../verify-client-attestation-jwt-base";
import {
  zWalletAttestationJwtHeaderV1_0,
  zWalletAttestationJwtPayloadV1_0,
} from "./z-wallet-attestation";

export interface VerifyClientAttestationJwtOptionsV1_0
  extends BaseVerifyClientAttestationJwtOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0;
  } & IoWalletSdkConfig;
}

export type VerifiedClientAttestationJwtV1_0 = Awaited<
  ReturnType<typeof verifyClientAttestationJwt>
>;

export async function verifyClientAttestationJwt(
  options: VerifyClientAttestationJwtOptionsV1_0,
) {
  return verifyClientAttestationJwtBase(
    options,
    zWalletAttestationJwtHeaderV1_0,
    zWalletAttestationJwtPayloadV1_0,
  );
}
