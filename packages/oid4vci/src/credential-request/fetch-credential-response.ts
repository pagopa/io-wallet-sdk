import { CallbackContext } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import type {
  CredentialRequestV1_0_2,
  CredentialResponseV1_0_2,
} from "./v1.0.2/z-credential";
import type {
  CredentialRequestV1_3_3,
  CredentialResponseV1_3_3,
} from "./v1.3.3/z-credential";

import * as v1_0_2 from "./v1.0.2/fetch-credential-response";
import * as v1_3_3 from "./v1.3.3/fetch-credential-response";

/**
 * Base options shared across all credential response fetch versions
 */
interface BaseFetchCredentialResponseOptions {
  accessToken: string;
  callbacks: Pick<CallbackContext, "fetch">;
  credentialEndpoint: string;
  dPoP: string;
}

/**
 * Options for fetching credential response with v1.0.2
 */
export interface FetchCredentialResponseOptionsV1_0_2
  extends BaseFetchCredentialResponseOptions {
  config: { itWalletSpecsVersion: "1.0.2" } & IoWalletSdkConfig;
  credentialRequest: CredentialRequestV1_0_2;
}

/**
 * Options for fetching credential response with v1.3.3
 */
export interface FetchCredentialResponseOptionsV1_3_3
  extends BaseFetchCredentialResponseOptions {
  config: { itWalletSpecsVersion: "1.3.3" } & IoWalletSdkConfig;
  credentialRequest: CredentialRequestV1_3_3;
}

/**
 * Union type for credential response fetch options
 */
export type FetchCredentialResponseOptions =
  | FetchCredentialResponseOptionsV1_0_2
  | FetchCredentialResponseOptionsV1_3_3;

/**
 * Union type for credential response return values
 */
export type CredentialResponse =
  | CredentialResponseV1_0_2
  | CredentialResponseV1_3_3;

/**
 * Fetches a credential response from the issuer according to the configured
 * Italian Wallet specification version.
 *
 * Version Differences:
 * - v1.0.2: Single credential response
 * - v1.3.3: Supports batch credential responses (multiple credentials per request)
 *
 * @param options - Configuration including endpoint, request, auth tokens, and version
 * @returns Version-specific credential response object
 * @throws {ItWalletSpecsVersionError} When version is not supported
 * @throws {FetchCredentialResponseError} When network or unexpected errors occur
 * @throws {UnexpectedStatusCodeError} When issuer returns non-200 status
 * @throws {ValidationError} When response doesn't match expected schema
 *
 * @example v1.0.2 - Basic credential fetch
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: '1.0.2' });
 * const credentialRequest = await createCredentialRequest({ config, ... });
 * const response = await fetchCredentialResponse({
 *   config,
 *   callbacks: { fetch: myFetchCallback },
 *   credentialEndpoint: "https://issuer.example.com/credential",
 *   credentialRequest,
 *   accessToken: "access_token_value",
 *   dPoP: "dpop_jwt_value"
 * });
 *
 * @example v1.3.3 - Batch credential fetch
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: '1.3.3' });
 * const credentialRequest = await createCredentialRequest({ config, ... });
 * const response = await fetchCredentialResponse({
 *   config,
 *   callbacks: { fetch: myFetchCallback },
 *   credentialEndpoint: "https://issuer.example.com/credential",
 *   credentialRequest,
 *   accessToken: "access_token_value",
 *   dPoP: "dpop_jwt_value"
 * });
 * // Response may contain multiple credentials if batch proofs were provided
 */

// Function overload for v1.0.2
export function fetchCredentialResponse(
  options: FetchCredentialResponseOptionsV1_0_2,
): Promise<CredentialResponseV1_0_2>;

// Function overload for v1.3.3
export function fetchCredentialResponse(
  options: FetchCredentialResponseOptionsV1_3_3,
): Promise<CredentialResponseV1_3_3>;

// Implementation signature (not callable by users)
export async function fetchCredentialResponse(
  options: FetchCredentialResponseOptions,
): Promise<CredentialResponse> {
  const { config } = options;

  switch (config.itWalletSpecsVersion) {
    case "1.0.2": {
      return v1_0_2.fetchCredentialResponse(
        options as FetchCredentialResponseOptionsV1_0_2,
      );
    }
    case "1.3.3": {
      return v1_3_3.fetchCredentialResponse(
        options as FetchCredentialResponseOptionsV1_3_3,
      );
    }
    default: {
      // Exhaustiveness check - ensures all versions are handled
      throw new ItWalletSpecsVersionError(
        "fetchCredentialResponse",
        (config as { itWalletSpecsVersion: string }).itWalletSpecsVersion,
        ["1.0.2", "1.3.3"],
      );
    }
  }
}
