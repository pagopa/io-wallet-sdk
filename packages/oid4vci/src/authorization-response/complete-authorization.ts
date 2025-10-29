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
import { zAccessCode } from "./z-access-code";

export interface CompleteAuthorizationOptions {
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The issuer the Wallet Instance started the
   * authorization flow (either via PAR or directly) with
   */
  iss: string;

  /**
   * The response_uri returned by the server after a successful
   * OID4VP Authorization Response is sent
   */
  response_uri: string;

  /**
   * The state sent by the Wallet Instance at the start
   * of the authorization flow (either via PAR or directly)
   */
  state: string;
}

/**
 * Combination of {@link CompleteAuthorizationOptions} and
 * {@link FetchAuthorizationResponseOptions}
 */
export type SendAuthorizationResponseAndExtractCodeOptions =
  FetchAuthorizationResponseOptions &
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
): ReturnType<typeof getJwtFromFormPost<typeof zAccessCode>> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const authorizationResponseResult = await fetch(options.response_uri);

    await hasStatusOrThrow(
      200,
      UnexpectedStatusCodeError,
    )(authorizationResponseResult);

    const result = await getJwtFromFormPost({
      formData: await authorizationResponseResult.text(),
      schema: zAccessCode,
    });
    const {
      decodedJwt: { payload: accessCode },
    } = result;

    if (accessCode.iss !== options.iss)
      throw new Oid4vciError(
        `Response result iss doesn't match passed counterpart. Expected: ${options.iss}, Got: ${accessCode.iss}`,
      );
    if (accessCode.state !== options.state)
      throw new Oid4vciError(
        `Response result state doesn't match passed counterpart. Expected: ${options.state}, Got: ${accessCode.state}`,
      );

    return result;
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
 * Convenience method that combines {@link completeAuthorization} and
 * oid4vp package's {@link fetchAuthorizationResponse} to retrieve the
 * access code starting from the authorization response and the response uri
 *
 * @param options {@link SendAuthorizationResponseAndExtractCodeOptions}
 * @returns An object containing the fetched JWT and its decoding. The JWT contains the access code
 *          for necessary for access token issuance
 */
export async function sendAuthorizationResponseAndExtractCode(
  options: SendAuthorizationResponseAndExtractCodeOptions,
): ReturnType<typeof getJwtFromFormPost<typeof zAccessCode>> {
  try {
    const authorizationResult = await fetchAuthorizationResponse(options);

    return completeAuthorization({
      ...options,
      response_uri: authorizationResult.redirect_uri,
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
