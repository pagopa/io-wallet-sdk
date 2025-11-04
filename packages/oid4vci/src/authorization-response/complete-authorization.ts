import { CallbackContext } from "@openid4vc/oauth2";
import { ValidationError, createFetcher } from "@openid4vc/utils";
import { getJwtFromFormPost } from "@pagopa/io-wallet-oauth2";
import {
  FetchAuthorizationResponseOptions,
  fetchAuthorizationResponse,
} from "@pagopa/io-wallet-oid4vp";
import {
  UnexpectedStatusCodeError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { Oid4vciError } from "../errors";
import {
  VerifyAuthorizationResponseFormPostJWTOptions,
  verifyAuthorizationResponseFormPostJWT,
} from "./verify-authorization-response";
import { AuthorizationResponse, zAuthorizationResponse } from "./z-access-code";

export interface CompleteAuthorizationOptions {
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The response_uri returned by the server after a successful
   * OID4VP Authorization Response is sent
   */
  response_uri: string;
}

/**
 * Combination of {@link CompleteAuthorizationOptions},
 * {@link FetchAuthorizationResponseOptions} and
 * {@link VerifyAuthorizationResponseFormPostJWTOptions}
 */
export type SendAuthorizationResponseAndExtractCodeOptions =
  FetchAuthorizationResponseOptions &
    Omit<
      VerifyAuthorizationResponseFormPostJWTOptions,
      "authorizationResponseCompact" | "authorizationResponseDecoded"
    > &
    Omit<CompleteAuthorizationOptions, "response_uri">;

/**
 * Method that completes the form_post.jwt based authorization
 * process for credentials issuance following the ITWallet
 * specification by retrieving the form from the provided uri,
 * extracting and parsing the contained JWT and verifying the
 * iss and state fields match the authorization session's expected
 * values.
 * See https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuance-low-level.html#
 * steps 6-7 for details.
 *
 * @param options {@link CompleteAuthorizationOptions}
 * @returns An object containing the fetched JWT and its decoding. The JWT contains the access code
 *          necessary for access token issuance
 */
export async function completeAuthorization(
  options: CompleteAuthorizationOptions,
): ReturnType<typeof getJwtFromFormPost<typeof zAuthorizationResponse>> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const authorizationResponseResult = await fetch(options.response_uri);

    await hasStatusOrThrow(
      200,
      UnexpectedStatusCodeError,
    )(authorizationResponseResult);

    return await getJwtFromFormPost({
      formData: await authorizationResponseResult.text(),
      schema: zAuthorizationResponse,
    });
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof Oid4vciError
    ) {
      throw error;
    }
    throw new Oid4vciError(
      `Unexpected error completing the authorization process: ${error instanceof Error ? `${error.name} : ${error.message}` : String(error)}`,
    );
  }
}

/**
 * Convenience method that combines {@link completeAuthorization},
 * oid4vp package's {@link fetchAuthorizationResponse} and {@link verifyAuthorizationResponseFormPostJWT} to retrieve the
 * access code starting from the authorization response and the response uri
 *
 * @param options {@link SendAuthorizationResponseAndExtractCodeOptions}
 * @returns An object containing the fetched JWT and its decoding. The JWT contains the access code
 *          for necessary for access token issuance
 */
export async function sendAuthorizationResponseAndExtractCode(
  options: SendAuthorizationResponseAndExtractCodeOptions,
): Promise<AuthorizationResponse> {
  try {
    const authorizationResult = await fetchAuthorizationResponse(options);

    const jwtAndPayload = await completeAuthorization({
      ...options,
      response_uri: authorizationResult.redirect_uri,
    });

    return verifyAuthorizationResponseFormPostJWT({
      authorizationResponseCompact: jwtAndPayload.jwt,
      authorizationResponseDecoded: jwtAndPayload.decodedJwt,
      callbacks: {
        verifyJwt: options.callbacks.verifyJwt,
      },
      iss: options.iss,
      signer: options.signer,
      state: options.state,
    });
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof Oid4vciError
    ) {
      throw error;
    }
    throw new Oid4vciError(
      `Unexpected error sending the authorization response and retrieving the acces code: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
