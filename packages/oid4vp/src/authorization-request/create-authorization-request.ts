import {
  type CallbackContext,
  type CreateJarRequestOptions,
  CreateJarRequestResult,
  JarAuthorizationRequest,
  JwtSignerFederation,
  JwtSignerX5c,
  createJarRequest,
  jwtHeaderFromJwtSigner,
  signedAuthorizationRequestJwtHeaderTyp,
} from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
  hasConfigVersion,
  objectToQueryParams,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError } from "../errors";
import {
  Openid4vpAuthorizationRequestPayload,
  zOpenid4vpAuthorizationRequestHeaderV1_0,
  zOpenid4vpAuthorizationRequestHeaderV1_3,
  zOpenid4vpAuthorizationRequestPayload,
} from "./z-authorization-request";

type BaseJarOptions<TSigner extends JwtSignerFederation | JwtSignerX5c> = {
  jwtSigner: TSigner;
} & Pick<
  CreateJarRequestOptions,
  "additionalJwtPayload" | "expiresInSeconds" | "now" | "requestUri"
>;

export type JarOptionsV1_0 = BaseJarOptions<JwtSignerFederation>;

export type JarOptionsV1_3 = BaseJarOptions<JwtSignerX5c>;

type JarOptions = JarOptionsV1_0 | JarOptionsV1_3;

interface BaseCreateAuthorizationRequestOptions<
  V extends ItWalletSpecsVersion,
  TJar extends JarOptions,
> {
  /**
   * Authorization request payload to be validated and serialized.
   */
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;

  /**
   * Required callbacks used to create a signed/encrypted Request Object.
   */
  callbacks: Partial<Pick<CallbackContext, "encryptJwe">> &
    Pick<CallbackContext, "signJwt">;

  config: IoWalletSdkConfig<V>;

  /**
   * The request is generated as a JAR authorization request.
   * When `additionalJwtPayload.aud` is missing, it is set to `requestUri`.
   */
  jar: TJar;

  /**
   * Authorization request URL scheme.
   * @default "openid4vp://"
   */
  scheme?: string;
}

/**
 * Options for creating an OpenID4VP authorization request URL.
 */
export type CreateAuthorizationRequestOptionsV1_0 =
  BaseCreateAuthorizationRequestOptions<
    ItWalletSpecsVersion.V1_0,
    JarOptionsV1_0
  >;

export type CreateAuthorizationRequestOptionsV1_3 =
  BaseCreateAuthorizationRequestOptions<
    ItWalletSpecsVersion.V1_3,
    JarOptionsV1_3
  >;

export type CreateAuthorizationRequestOptions =
  | CreateAuthorizationRequestOptionsV1_0
  | CreateAuthorizationRequestOptionsV1_3;

interface BaseCreateAuthorizationRequestResult<TJar extends JarOptions> {
  authorizationRequest: string;
  authorizationRequestObject: JarAuthorizationRequest;
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  jar: CreateJarRequestResult & TJar;
}

export type CreateAuthorizationRequestResultV1_0 =
  BaseCreateAuthorizationRequestResult<JarOptionsV1_0>;

export type CreateAuthorizationRequestResultV1_3 =
  BaseCreateAuthorizationRequestResult<JarOptionsV1_3>;

export type CreateAuthorizationRequestResult =
  | CreateAuthorizationRequestResultV1_0
  | CreateAuthorizationRequestResultV1_3;

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
  options: CreateAuthorizationRequestOptionsV1_0,
): Promise<CreateAuthorizationRequestResultV1_0>;

export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptionsV1_3,
): Promise<CreateAuthorizationRequestResultV1_3>;

export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptions,
): Promise<CreateAuthorizationRequestResult> {
  try {
    const { config } = options;

    if (hasConfigVersion(options, ItWalletSpecsVersion.V1_0)) {
      return await createAuthorizationRequestWithHeader(
        options,
        zOpenid4vpAuthorizationRequestHeaderV1_0,
      );
    }

    if (hasConfigVersion(options, ItWalletSpecsVersion.V1_3)) {
      return await createAuthorizationRequestWithHeader(
        options,
        zOpenid4vpAuthorizationRequestHeaderV1_3,
      );
    }

    throw new ItWalletSpecsVersionError(
      "createAuthorizationRequest",
      config.itWalletSpecsVersion,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  } catch (error) {
    if (error instanceof ValidationError) {
      throw new Oid4vpError(`Invalid authorization request: ${error.message}`);
    }
    throw error;
  }
}

async function createAuthorizationRequestWithHeader<TJar extends JarOptions>(
  options: BaseCreateAuthorizationRequestOptions<ItWalletSpecsVersion, TJar>,
  headerSchema:
    | typeof zOpenid4vpAuthorizationRequestHeaderV1_0
    | typeof zOpenid4vpAuthorizationRequestHeaderV1_3,
): Promise<BaseCreateAuthorizationRequestResult<TJar>> {
  const { callbacks, jar, scheme = "openid4vp://" } = options;

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
