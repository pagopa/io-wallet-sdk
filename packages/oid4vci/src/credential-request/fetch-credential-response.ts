import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { FetchCredentialResponseError } from "../errors";
import {
  CredentialRequest,
  CredentialResponse,
  zCredentialResponse,
} from "./z-credential";

export interface FetchCredentialResponseOptions {
  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<CallbackContext, "fetch">;
  /**
   * The client attestation Demonstration of Proof-of-Possession (DPoP) token
   * Used for OAuth-Client-Attestation-PoP header to prove possession of the client key
   */
  clientAttestationDPoP: string;
  /**
   * The credential endpoint URL
   */
  credentialEndpoint: string;

  /**
   * Credential request body
   */
  credentialRequest: CredentialRequest;

  /**
   * DPoP proof with addition of ath claim
   */
  dPoP: string;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation: string;
}

export async function fetchTokenResponse(
  options: FetchCredentialResponseOptions,
): Promise<CredentialResponse> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const credentialResponse = await fetch(options.credentialEndpoint, {
      body: JSON.stringify(options.credentialRequest),
      headers: {
        [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.JSON,
        [HEADERS.DPOP]: options.dPoP,
        [HEADERS.OAUTH_CLIENT_ATTESTATION]: options.walletAttestation,
        [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]: options.clientAttestationDPoP,
      },
      method: "POST",
    });

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(credentialResponse);

    const credentialResponseJson = await credentialResponse.json();

    const parsedCredentialResponse = zCredentialResponse.safeParse(
      credentialResponseJson,
    );
    if (!parsedCredentialResponse.success) {
      throw new ValidationError(
        `Failed to parse credential response`,
        parsedCredentialResponse.error,
      );
    }

    return parsedCredentialResponse.data;
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchCredentialResponseError(
      `Unexpected error during credential response: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
