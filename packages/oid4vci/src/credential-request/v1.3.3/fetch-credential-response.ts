import { CallbackContext } from "@openid4vc/oauth2";

import type {
  CredentialRequestV1_3_3,
  CredentialResponseV1_3_3,
} from "./z-credential";

import { sharedFetchCredentialResponse } from "../shared/fetch-credential-response";
import { zCredentialResponseV1_3_3 } from "./z-credential";

/**
 * Options for fetching a credential response with v1.3.3
 */
export interface FetchCredentialResponseOptionsV1_3_3 {
  accessToken: string;
  callbacks: Pick<CallbackContext, "fetch">;
  credentialEndpoint: string;
  credentialRequest: CredentialRequestV1_3_3;
  dPoP: string;
}

/**
 * Fetches a credential response from the issuer (v1.3.3).
 *
 * This is a high-level function that performs the HTTP POST request
 * and validates the response according to IT-Wallet v1.3.3 specs.
 *
 * Supports batch credential issuance when multiple proofs are provided.
 *
 * @param options - Configuration including endpoint, request, and auth tokens
 * @returns Parsed credential response (immediate, batch, or deferred)
 * @throws {FetchCredentialResponseError} When network or unexpected errors occur
 * @throws {UnexpectedStatusCodeError} When issuer returns non-200 status
 * @throws {ValidationError} When response doesn't match expected schema
 */
export async function fetchCredentialResponse(
  options: FetchCredentialResponseOptionsV1_3_3,
): Promise<CredentialResponseV1_3_3> {
  return sharedFetchCredentialResponse({
    ...options,
    responseSchema: zCredentialResponseV1_3_3,
  });
}
