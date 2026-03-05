import { jwtHeaderFromJwtSigner } from "@openid4vc/oauth2";
import {
  type CallbackContext,
  type CreateJarRequestOptions,
  CreateJarRequestResult,
  JarAuthorizationRequest,
  createJarRequest,
  signedAuthorizationRequestJwtHeaderTyp,
} from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ValidationError,
  objectToQueryParams,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError } from "../errors";
import {
  AuthorizationRequestObject,
  zOpenid4vpAuthorizationRequestHeaderV1_0,
  zOpenid4vpAuthorizationRequestHeaderV1_3,
  zOpenid4vpAuthorizationRequestPayload,
} from "./z-request-object";

type JarOptions = Pick<
  CreateJarRequestOptions,
  | "additionalJwtPayload"
  | "expiresInSeconds"
  | "jwtSigner"
  | "now"
  | "requestUri"
>;

/**
 * Options for creating an OpenID4VP authorization request URL.
 */
export interface CreateAuthorizationRequestOptions {
  /**
   * Authorization request payload to be validated and serialized.
   */
  authorizationRequestPayload: AuthorizationRequestObject;

  /**
   * Required callbacks used to create a signed/encrypted Request Object.
   */
  callbacks: Partial<Pick<CallbackContext, "encryptJwe">> &
    Pick<CallbackContext, "signJwt">;

  config: IoWalletSdkConfig;

  /**
   * The request is generated as a JAR authorization request.
   * When `additionalJwtPayload.aud` is missing, it is set to `requestUri`.
   */
  jar: JarOptions;

  /**
   * Authorization request URL scheme.
   * @default "openid4vp://"
   */
  scheme?: string;
}

export interface CreateAuthorizationRequestResult {
  authorizationRequest: string;
  authorizationRequestObject: JarAuthorizationRequest;
  authorizationRequestPayload: AuthorizationRequestObject;
  jar: CreateJarRequestResult & JarOptions;
}

/**
 * Creates an OpenID4VP authorization request URL.
 *
 * This function creates a JAR request object through
 * `createJarRequest` and serializes it into the URL query parameters.
 *
 * @param options {@link CreateAuthorizationRequestOptions}
 * @returns Authorization request URL plus request object details used to build it
 * @throws When authorization request payload validation fails
 * @throws When JAR creation fails
 */
export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptions,
): Promise<CreateAuthorizationRequestResult> {
  try {
    const { callbacks, config, jar, scheme = "openid4vp://" } = options;

    const headerSchema = config.isVersion(ItWalletSpecsVersion.V1_0)
      ? zOpenid4vpAuthorizationRequestHeaderV1_0
      : zOpenid4vpAuthorizationRequestHeaderV1_3;

    const authorizationRequestHeader = parseWithErrorHandling(headerSchema, {
      ...jwtHeaderFromJwtSigner(jar.jwtSigner),
      typ: signedAuthorizationRequestJwtHeaderTyp,
    });

    const authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestPayload,
      options.authorizationRequestPayload,
    );

    const additionalJwtPayload = !jar.additionalJwtPayload?.aud
      ? { ...jar.additionalJwtPayload, aud: jar.requestUri }
      : jar.additionalJwtPayload;

    const jarResult = await createJarRequest({
      ...jar,
      additionalJwtPayload,
      authorizationRequestHeader,
      authorizationRequestPayload,
      callbacks,
    });

    return {
      authorizationRequest: createAuthorizationRequestUrl(
        scheme,
        jarResult.jarAuthorizationRequest,
      ),
      authorizationRequestObject: jarResult.jarAuthorizationRequest,
      authorizationRequestPayload,
      jar: { ...jar, ...jarResult },
    };
  } catch (error) {
    if (error instanceof ValidationError) {
      throw new Oid4vpError(
        "Invalid authorization request. Could not parse openid4vp authorization request.",
      );
    }
    throw error;
  }
}

function createAuthorizationRequestUrl(
  scheme: string,
  request: JarAuthorizationRequest,
) {
  const url = new URL(scheme);

  const searchParams = new URLSearchParams([
    ...url.searchParams.entries(),
    ...objectToQueryParams(request).entries(),
  ]);

  url.search = searchParams.toString();

  return url.toString();
}
