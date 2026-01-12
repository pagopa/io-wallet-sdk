import { CallbackContext } from "@openid4vc/oauth2";

import type {
  CredentialRequestV1_0_2,
  CredentialResponseV1_0_2,
} from "./z-credential";

import { sharedFetchCredentialResponse } from "../shared/fetch-credential-response";
import { zCredentialResponseV1_0_2 } from "./z-credential";

/**
 * Options for fetching a credential response with v1.0.2
 */
export interface FetchCredentialResponseOptionsV1_0_2 {
  accessToken: string;
  callbacks: Pick<CallbackContext, "fetch">;
  credentialEndpoint: string;
  credentialRequest: CredentialRequestV1_0_2;
  dPoP: string;
}

/**
 * Fetches a credential response from the issuer (v1.0.2).
 *
 * This is a high-level function that performs the HTTP POST request
 * and validates the response according to IT-Wallet v1.0.2 specs.
 *
 * @param options - Configuration including endpoint, request, and auth tokens
 * @returns Parsed credential response (immediate or deferred)
 * @throws {FetchCredentialResponseError} When network or unexpected errors occur
 * @throws {UnexpectedStatusCodeError} When issuer returns non-200 status
 * @throws {ValidationError} When response doesn't match expected schema
 */
export async function fetchCredentialResponse(
  options: FetchCredentialResponseOptionsV1_0_2,
): Promise<CredentialResponseV1_0_2> {
  return sharedFetchCredentialResponse({
    ...options,
    responseSchema: zCredentialResponseV1_0_2,
  });
}
