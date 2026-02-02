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
