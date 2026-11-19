import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

import {
  JarRequestObjectTyp,
  jwtAuthorizationRequestJwtHeaderTyp,
  signedAuthorizationRequestJwtHeaderTyp,
} from "../jar/z-jar";

export interface RequestObjectTypPolicy {
  /**
   * `typ` header values accepted when verifying a PAR request object.
   */
  accept: readonly JarRequestObjectTyp[];

  /**
   * `typ` header value used when signing a PAR request object.
   */
  sign: JarRequestObjectTyp;
}

// Before 1.4.7 `typ` was optional and implicitly "JWT".
const LEGACY: RequestObjectTypPolicy = {
  accept: [
    signedAuthorizationRequestJwtHeaderTyp,
    jwtAuthorizationRequestJwtHeaderTyp,
  ],
  sign: jwtAuthorizationRequestJwtHeaderTyp,
};

// Since 1.4.7 `typ` is REQUIRED and MUST be oauth-authz-req+jwt.
const STRICT: RequestObjectTypPolicy = {
  accept: [signedAuthorizationRequestJwtHeaderTyp],
  sign: signedAuthorizationRequestJwtHeaderTyp,
};

export const requestObjectTyps: Record<
  ItWalletSpecsVersion,
  RequestObjectTypPolicy
> = {
  [ItWalletSpecsVersion.V1_0]: LEGACY,
  [ItWalletSpecsVersion.V1_3]: LEGACY,
  [ItWalletSpecsVersion.V1_4]: STRICT,
};
