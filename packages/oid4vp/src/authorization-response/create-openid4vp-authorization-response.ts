import { Oauth2Error } from "@pagopa/io-wallet-oauth2";
import {
  type CallbackContext,
  ContentType,
  type JweEncryptor,
  type Jwk,
  type JwkSet,
  type JwtSigner,
  addSecondsToDate,
  dateToSeconds,
  encodeToBase64Url,
  jwtHeaderFromJwtSigner,
  parseWithErrorHandling,
  zJwkSet,
} from "@pagopa/io-wallet-utils";

import {
  ClientIdPrefix,
  extractClientIdPrefix,
} from "../authorization-request/parse-authorization-request";
import { Openid4vpAuthorizationRequestPayload } from "../authorization-request/z-authorization-request";
import { extractEncryptionJwkFromJwks } from "../jarm/jarm-extract-jwks";

export type VpTokenPresentationEntry = Record<string, unknown> | string;

export type VpToken =
  | [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]]
  | Record<
      string,
      | [VpTokenPresentationEntry, ...VpTokenPresentationEntry[]]
      | VpTokenPresentationEntry
    >
  | VpTokenPresentationEntry;

export interface Openid4vpAuthorizationResponsePayload {
  [key: string]: unknown;
  access_token?: string;
  expires_in?: number;
  id_token?: string;
  presentation_submission?: Record<string, unknown> | string;
  refresh_token?: string;
  state?: string;
  token_type?: string;
  vp_token: VpToken;
}

export interface JarmClientMetadata {
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  authorization_signed_response_alg?: string;
  encrypted_response_enc_values_supported?: string[];
  jwks?: JwkSet;
  jwks_uri?: string;
}

export interface JarmServerMetadata {
  authorization_encryption_alg_values_supported: string[];
  authorization_encryption_enc_values_supported: string[];
  authorization_signed_response_alg_values_supported?: string[];
}

export interface CreateOpenid4vpAuthorizationResponseOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  authorizationResponsePayload: {
    state?: never;
  } & Openid4vpAuthorizationResponsePayload;
  callbacks: Pick<CallbackContext, "encryptJwe" | "fetch" | "signJwt">;
  clientMetadata?: JarmClientMetadata;
  jarm?: {
    audience?: string;
    authorizationServer?: string;
    encryption?: {
      jwk?: Jwk;
      nonce: string;
    };
    expiresInSeconds?: number;
    jwtSigner?: JwtSigner;
    serverMetadata: JarmServerMetadata;
  };
  origin?: string;
}

export interface CreateOpenid4vpAuthorizationResponseResult {
  authorizationResponsePayload: Openid4vpAuthorizationResponsePayload;
  jarm?: {
    encryptionJwk?: Jwk;
    responseJwt: string;
  };
}

const jarmResponseModes = new Set([
  "jwt",
  "query.jwt",
  "fragment.jwt",
  "form_post.jwt",
  "direct_post.jwt",
  "dc_api.jwt",
]);

function assertValueSupported(options: {
  actual: string;
  errorMessage: string;
  supported: string[];
}): string {
  const { actual, errorMessage, supported } = options;
  const found = supported.find((value) => value === actual);
  if (!found) {
    throw new Oauth2Error(errorMessage);
  }
  return found;
}

async function fetchJwks(
  jwksUrl: string,
  fetchCallback: CallbackContext["fetch"],
): Promise<JwkSet> {
  if (!fetchCallback) {
    throw new Oauth2Error(
      `Missing fetch callback required to resolve jwks_uri '${jwksUrl}'.`,
    );
  }

  const response = await fetchCallback(jwksUrl, {
    headers: {
      Accept: `${ContentType.JwkSet}, ${ContentType.Json};q=0.9`,
    },
  });

  if (!response.ok) {
    throw new Oauth2Error(
      `Fetching JWKs from jwks_uri '${jwksUrl}' resulted in an unsuccessful response with status code '${response.status}'.`,
    );
  }

  return parseWithErrorHandling(
    zJwkSet,
    await response.json(),
    `Validation of JWKs from jwks_uri '${jwksUrl}' failed`,
  );
}

async function createJarmAuthorizationResponse(options: {
  callbacks: Pick<CallbackContext, "encryptJwe" | "signJwt">;
  jarmAuthorizationResponse: Openid4vpAuthorizationResponsePayload;
  jweEncryptor?: JweEncryptor;
  jwtSigner?: JwtSigner;
}): Promise<{
  encryptionJwk?: Jwk;
  jarmAuthorizationResponseJwt: string;
}> {
  const { callbacks, jarmAuthorizationResponse, jweEncryptor, jwtSigner } =
    options;

  if (!jwtSigner && jweEncryptor) {
    const { encryptionJwk, jwe } = await callbacks.encryptJwe(
      jweEncryptor,
      JSON.stringify(jarmAuthorizationResponse),
    );

    return {
      encryptionJwk,
      jarmAuthorizationResponseJwt: jwe,
    };
  }

  if (jwtSigner && !jweEncryptor) {
    const { jwt } = await callbacks.signJwt(jwtSigner, {
      header: jwtHeaderFromJwtSigner(jwtSigner),
      payload: jarmAuthorizationResponse,
    });

    return {
      jarmAuthorizationResponseJwt: jwt,
    };
  }

  if (!jwtSigner || !jweEncryptor) {
    throw new Oauth2Error(
      "JWT signer and/or encryptor are required to create a JARM auth response.",
    );
  }

  const signed = await callbacks.signJwt(jwtSigner, {
    header: jwtHeaderFromJwtSigner(jwtSigner),
    payload: jarmAuthorizationResponse,
  });

  const { encryptionJwk, jwe } = await callbacks.encryptJwe(
    jweEncryptor,
    signed.jwt,
  );

  return {
    encryptionJwk,
    jarmAuthorizationResponseJwt: jwe,
  };
}

// eslint-disable-next-line complexity
export async function createOpenid4vpAuthorizationResponse(
  options: CreateOpenid4vpAuthorizationResponseOptions,
): Promise<CreateOpenid4vpAuthorizationResponseResult> {
  const { authorizationRequestPayload, jarm } = options;
  const authorizationResponsePayload = {
    ...options.authorizationResponsePayload,
    state: authorizationRequestPayload.state,
  };

  const { prefix: clientIdPrefix } = extractClientIdPrefix(
    authorizationRequestPayload.client_id,
  );

  if (
    authorizationRequestPayload.response_mode &&
    jarmResponseModes.has(authorizationRequestPayload.response_mode) &&
    !jarm
  ) {
    throw new Oauth2Error(
      `Missing jarm options for creating Jarm response with response mode '${authorizationRequestPayload.response_mode}'`,
    );
  }

  if (!jarm) {
    return { authorizationResponsePayload };
  }

  if (
    clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION &&
    !options.clientMetadata
  ) {
    throw new Oauth2Error(
      "When OpenID Federation is used as the client id prefix (https/openid_federation), passing externally fetched and verified 'clientMetadata' to 'createOpenid4vpAuthorizationResponse' is required.",
    );
  }

  const clientMetadata =
    options.clientMetadata ??
    (authorizationRequestPayload.client_metadata as
      | JarmClientMetadata
      | undefined);

  if (!clientMetadata) {
    throw new Oauth2Error(
      "Missing client metadata in the request params to assert Jarm metadata support.",
    );
  }

  const jwks = clientMetadata.jwks
    ? clientMetadata.jwks
    : clientMetadata.jwks_uri
      ? await fetchJwks(clientMetadata.jwks_uri, options.callbacks.fetch)
      : undefined;

  if (!jwks) {
    throw new Oauth2Error(
      "Missing 'jwks' or 'jwks_uri' in client metadata. Cannot extract encryption JWK.",
    );
  }

  const encryptionJwk =
    jarm.encryption?.jwk ??
    extractEncryptionJwkFromJwks(jwks, {
      supportedAlgValues:
        jarm.serverMetadata.authorization_encryption_alg_values_supported ??
        (clientMetadata.authorization_encrypted_response_alg
          ? [clientMetadata.authorization_encrypted_response_alg]
          : undefined),
    });

  if (!encryptionJwk) {
    throw new Oauth2Error(
      "No encryption JWK provided and could not extract encryption JWK from client metadata. Failed to create JARM response.",
    );
  }

  const enc = clientMetadata.encrypted_response_enc_values_supported
    ? (jarm.serverMetadata.authorization_encryption_enc_values_supported.find(
        (value) =>
          clientMetadata.encrypted_response_enc_values_supported?.includes(
            value,
          ),
      ) ??
      clientMetadata.encrypted_response_enc_values_supported[0] ??
      "A128GCM")
    : (clientMetadata.authorization_encrypted_response_enc ?? "A128GCM");

  assertValueSupported({
    actual: enc,
    errorMessage: `Invalid 'enc' value ${enc}. Supported values are ${jarm.serverMetadata.authorization_encryption_enc_values_supported.join(", ")}`,
    supported:
      jarm.serverMetadata.authorization_encryption_enc_values_supported,
  });

  const alg =
    encryptionJwk.alg ??
    clientMetadata.authorization_encrypted_response_alg ??
    "ECDH-ES";

  assertValueSupported({
    actual: alg,
    errorMessage: `Invalid 'alg' value ${alg}. Supported values are ${jarm.serverMetadata.authorization_encryption_alg_values_supported.join(", ")}`,
    supported:
      jarm.serverMetadata.authorization_encryption_alg_values_supported,
  });

  if (
    clientMetadata.authorization_signed_response_alg &&
    jarm.jwtSigner &&
    clientMetadata.authorization_signed_response_alg !== jarm.jwtSigner.alg
  ) {
    throw new Oauth2Error(
      `Invalid signed response alg value ${jarm.jwtSigner.alg}. Expected ${clientMetadata.authorization_signed_response_alg}.`,
    );
  }

  const additionalJwtPayload = jarm.jwtSigner
    ? {
        aud:
          jarm.audience ??
          (() => {
            throw new Oauth2Error(
              "Missing required aud in JARM configuration for creating OpenID4VP authorization response.",
            );
          })(),
        exp: jarm.expiresInSeconds
          ? dateToSeconds(addSecondsToDate(new Date(), jarm.expiresInSeconds))
          : dateToSeconds(addSecondsToDate(new Date(), 600)),
        iss:
          jarm.authorizationServer ??
          (() => {
            throw new Oauth2Error(
              "Missing required iss in JARM configuration for creating OpenID4VP authorization response.",
            );
          })(),
      }
    : undefined;

  const jarmResponsePayload = {
    ...authorizationResponsePayload,
    ...additionalJwtPayload,
  };

  const { encryptionJwk: usedEncryptionJwk, jarmAuthorizationResponseJwt } =
    await createJarmAuthorizationResponse({
      callbacks: {
        encryptJwe: options.callbacks.encryptJwe,
        signJwt: options.callbacks.signJwt,
      },
      jarmAuthorizationResponse: jarmResponsePayload,
      jweEncryptor: jarm.encryption
        ? {
            alg,
            apu: jarm.encryption.nonce
              ? encodeToBase64Url(jarm.encryption.nonce)
              : undefined,
            apv: encodeToBase64Url(authorizationRequestPayload.nonce),
            enc,
            method: "jwk",
            publicJwk: encryptionJwk,
          }
        : undefined,
      jwtSigner: jarm.jwtSigner,
    });

  return {
    authorizationResponsePayload: jarmResponsePayload,
    jarm: {
      encryptionJwk: usedEncryptionJwk,
      responseJwt: jarmAuthorizationResponseJwt,
    },
  };
}
