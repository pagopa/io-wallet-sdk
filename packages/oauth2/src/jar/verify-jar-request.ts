import {
  CallbackContext,
  JwtSigner,
  JwtSignerWithJwk,
  decodeJwt,
  verifyJwt,
  zCompactJwe,
  zCompactJwt,
} from "@openid4vc/oauth2";

import { Oauth2Error } from "../errors";
import {
  JarRequestObjectPayload,
  jwtAuthorizationRequestJwtHeaderTyp,
  signedAuthorizationRequestJwtHeaderTyp,
  zJarRequestObjectPayload,
} from "./z-jar";

export interface VerifyJarRequestOptions {
  authorizationRequestJwt: string;
  callbacks: Pick<CallbackContext, "verifyJwt">;
  jarRequestParams: {
    client_id?: string;
  };
  jwtSigner: JwtSigner;
  now?: Date;
}

export interface VerifiedJarRequest {
  authorizationRequestPayload: JarRequestObjectPayload;
  jwt: ReturnType<typeof decodeJwt<undefined, typeof zJarRequestObjectPayload>>;
  signer: JwtSignerWithJwk;
}

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(
  options: VerifyJarRequestOptions,
): Promise<VerifiedJarRequest> {
  const { authorizationRequestJwt, callbacks, jarRequestParams, jwtSigner } =
    options;

  /* Encryption is not supported */
  const requestObjectIsEncrypted = zCompactJwe.safeParse(
    authorizationRequestJwt,
  ).success;
  if (requestObjectIsEncrypted) {
    throw new Oauth2Error("Encrypted JWE request objects are not supported.");
  }

  const requestIsSigned = zCompactJwt.safeParse(
    authorizationRequestJwt,
  ).success;
  if (!requestIsSigned) {
    throw new Oauth2Error("JAR request object is not a valid JWT.");
  }

  const { authorizationRequestPayload, jwt, signer } =
    await verifyJarRequestObject({
      authorizationRequestJwt,
      callbacks,
      jwtSigner,
    });

  if (!authorizationRequestPayload.client_id) {
    throw new Oauth2Error(
      'Jar Request Object is missing the required "client_id" field.',
    );
  }

  // Expect the client_id from the jar request to match the payload
  if (jarRequestParams.client_id !== authorizationRequestPayload.client_id) {
    throw new Oauth2Error(
      "client_id does not match the request object client_id.",
    );
  }

  if (jwt.payload.iss !== authorizationRequestPayload.client_id) {
    throw new Oauth2Error("iss claim in request JWT does not match client_id");
  }

  // RFC 9101 §4: exp claim MUST be present and not in the past
  if (jwt.payload.exp === undefined) {
    throw new Oauth2Error("exp claim in request JWT is missing");
  }

  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (nowSeconds > jwt.payload.exp) {
    throw new Oauth2Error("exp claim in request JWT is expired");
  }

  // IT-Wallet requirement: iat MUST be present
  if (jwt.payload.iat === undefined) {
    throw new Oauth2Error("iat claim in request JWT is missing");
  }

  // IT-Wallet requirement: iat MUST not be more than 5 minutes in the past
  const MAX_IAT_AGE_SECONDS = 5 * 60;
  if (nowSeconds - jwt.payload.iat > MAX_IAT_AGE_SECONDS) {
    throw new Oauth2Error(
      "iat claim in request JWT is too old (must be within 5 minutes)",
    );
  }

  // IT-Wallet requirement: iat MUST not be more than clock-skew tolerance in the future
  const CLOCK_SKEW_TOLERANCE_SECONDS = 60;
  if (jwt.payload.iat - nowSeconds > CLOCK_SKEW_TOLERANCE_SECONDS) {
    throw new Oauth2Error("iat claim in request JWT is too far in the future");
  }

  return {
    authorizationRequestPayload,
    jwt,
    signer,
  };
}

async function verifyJarRequestObject(options: {
  authorizationRequestJwt: string;
  callbacks: Pick<CallbackContext, "verifyJwt">;
  jwtSigner: JwtSigner;
}) {
  const { authorizationRequestJwt, callbacks, jwtSigner } = options;

  const jwt = decodeJwt({
    jwt: authorizationRequestJwt,
    payloadSchema: zJarRequestObjectPayload,
  });

  const { signer } = await verifyJwt({
    compact: authorizationRequestJwt,
    header: jwt.header,
    payload: jwt.payload,
    signer: jwtSigner,

    verifyJwtCallback: callbacks.verifyJwt,
  });

  // Some existing deployments may alternatively be using both type
  if (
    jwt.header.typ !== signedAuthorizationRequestJwtHeaderTyp &&
    jwt.header.typ !== jwtAuthorizationRequestJwtHeaderTyp
  ) {
    throw new Oauth2Error(
      `Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt" or "jwt", received "${jwt.header.typ}".`,
    );
  }

  return {
    authorizationRequestPayload: jwt.payload,
    jwt,
    signer,
  };
}
