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
  ValidationError,
  createVersionDispatcher,
  objectToQueryParams,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError } from "../errors";
import { ClientIdPrefix, extractClientIdPrefix } from "./client-id-prefix";
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

export type JarOptionsV1_3 = BaseJarOptions<JwtSignerFederation | JwtSignerX5c>;

export type JarOptionsV1_4 = JarOptionsV1_3;

type JarOptions = JarOptionsV1_0 | JarOptionsV1_3 | JarOptionsV1_4;

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

export type CreateAuthorizationRequestOptionsV1_4 =
  BaseCreateAuthorizationRequestOptions<
    ItWalletSpecsVersion.V1_4,
    JarOptionsV1_4
  >;

export type CreateAuthorizationRequestOptions =
  | CreateAuthorizationRequestOptionsV1_0
  | CreateAuthorizationRequestOptionsV1_3
  | CreateAuthorizationRequestOptionsV1_4;

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

export type CreateAuthorizationRequestResultV1_4 =
  BaseCreateAuthorizationRequestResult<JarOptionsV1_4>;

export type CreateAuthorizationRequestResult =
  | CreateAuthorizationRequestResultV1_0
  | CreateAuthorizationRequestResultV1_3
  | CreateAuthorizationRequestResultV1_4;

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
const dispatchCreateAuthorizationRequest = createVersionDispatcher<
  CreateAuthorizationRequestOptions,
  Promise<CreateAuthorizationRequestResult>
>({
  [ItWalletSpecsVersion.V1_0]: async (o) =>
    createAuthorizationRequestWithHeader(
      o as CreateAuthorizationRequestOptionsV1_0,
      zOpenid4vpAuthorizationRequestHeaderV1_0,
    ),
  [ItWalletSpecsVersion.V1_3]: async (o) =>
    createAuthorizationRequestWithHeader(
      o as CreateAuthorizationRequestOptionsV1_3,
      zOpenid4vpAuthorizationRequestHeaderV1_3,
    ),
  // V1_4 reuses the V1_3 JAR header schema; the conditional x5c rule is a normative 1.4.4 LTS backport.
  [ItWalletSpecsVersion.V1_4]: async (o) =>
    createAuthorizationRequestWithHeader(
      o as CreateAuthorizationRequestOptionsV1_4,
      zOpenid4vpAuthorizationRequestHeaderV1_3,
    ),
});

/**
 * Creates an OpenID4VP authorization request URL for the configured IT-Wallet version.
 *
 * This function creates a JAR request object through `createJarRequest` and
 * serializes it into authorization request URL query parameters.
 *
 * @param options - Version-specific authorization request creation options.
 * @returns Authorization request URL plus request object details used to build it.
 * @throws {Oid4vpError} If authorization request payload validation fails.
 */
export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptionsV1_0,
): Promise<CreateAuthorizationRequestResultV1_0>;

export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptionsV1_3,
): Promise<CreateAuthorizationRequestResultV1_3>;

export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptionsV1_4,
): Promise<CreateAuthorizationRequestResultV1_4>;

export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptions,
): Promise<CreateAuthorizationRequestResult> {
  try {
    return await dispatchCreateAuthorizationRequest(options);
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

  validateJarSignerForAuthorizationRequest(
    options.config.itWalletSpecsVersion,
    jar.jwtSigner,
    authorizationRequestPayload,
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

function validateJarSignerForAuthorizationRequest(
  specsVersion: ItWalletSpecsVersion,
  jwtSigner: JwtSignerFederation | JwtSignerX5c,
  payload: Openid4vpAuthorizationRequestPayload,
) {
  if (specsVersion === ItWalletSpecsVersion.V1_0) {
    return;
  }

  const { prefix } = extractClientIdPrefix(payload.client_id);

  if (prefix === ClientIdPrefix.X509_HASH && jwtSigner.method !== "x5c") {
    throw new Oid4vpError(
      "x509_hash client_id requires a JAR signer with method x5c",
    );
  }

  if (
    prefix !== ClientIdPrefix.X509_HASH &&
    jwtSigner.method !== "federation"
  ) {
    throw new Oid4vpError(
      "openid_federation and legacy client_id values require a JAR signer with method federation",
    );
  }
}
