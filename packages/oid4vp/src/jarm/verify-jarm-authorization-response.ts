import { jwtSignerFromJwt } from "@openid4vc/oauth2";
import {
  type CallbackContext,
  type Jwk,
  Oauth2Error,
  decodeJwt,
  decodeJwtHeader,
  zCompactJwe,
  zCompactJwt,
  zJwtHeader,
} from "@pagopa/io-wallet-oauth2";
import { stringToJsonWithErrorHandling } from "@pagopa/io-wallet-utils";
import z from "zod";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request";
import { extractEncryptionJwkFromJwks } from "./jarm-extract-jwks";
import {
  JarmAuthorizationResponse,
  JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
  zJarmAuthorizationResponseEncryptedOnly,
} from "./z-jarm";

/**
 * Supported JARM serialization/processing modes.
 */
export enum JarmMode {
  Encrypted = "Encrypted",
  Signed = "Signed",
  SignedEncrypted = "SignedEncrypted",
}

/**
 * The client decrypts the JWT using the default key for the respective issuer or,
 * if applicable, determined by the kid JWT header parameter.
 * The key might be a private key, where the corresponding public key is registered
 * with the expected issuer of the response ("use":"enc" via the client's metadata jwks or jwks_uri)
 * or a key derived from its client secret (see Section 2.2).
 */
const decryptJarmAuthorizationResponseJwt = async (options: {
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  callbacks: Pick<CallbackContext, "decryptJwe">;
  jarmAuthorizationResponseJwt: string;
}) => {
  const {
    authorizationRequestPayload,
    callbacks,
    jarmAuthorizationResponseJwt,
  } = options;

  let encryptionJwk: Jwk | undefined;
  const { header } = decodeJwtHeader({
    jwt: jarmAuthorizationResponseJwt,
  });

  if (authorizationRequestPayload.client_metadata?.jwks) {
    encryptionJwk = extractEncryptionJwkFromJwks(
      authorizationRequestPayload.client_metadata.jwks,
      {
        kid: header.kid,
        // This value was removed in draft 26, but if it's still provided, we can use it to determine the key to use
        supportedAlgValues: authorizationRequestPayload.client_metadata
          .authorization_encrypted_response_alg
          ? [
              authorizationRequestPayload.client_metadata
                .authorization_encrypted_response_alg,
            ]
          : undefined,
      },
    );
  }

  const result = await callbacks.decryptJwe(jarmAuthorizationResponseJwt, {
    jwk: encryptionJwk,
  });

  if (!result.decrypted) {
    throw new Oauth2Error("Failed to decrypt jarm auth response.");
  }

  return {
    decryptionJwk: result.decryptionJwk,
    payload: result.payload,
  };
};

export interface VerifyJarmAuthorizationResponseOptions {
  /**
   * Parsed authorization request payload used to resolve metadata and key material.
   */
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  /**
   * Callbacks required for JWE decryption and JWT signature verification.
   */
  callbacks: Pick<CallbackContext, "decryptJwe" | "verifyJwt">;
  /**
   * Compact serialized JARM response received from the verifier.
   */
  jarmAuthorizationResponseJwt: string;
}

/**
 * Verified JARM authorization response data returned by {@link verifyJarmAuthorizationResponse}.
 */
export type VerifiedJarmAuthorizationResponse = Awaited<
  ReturnType<typeof verifyJarmAuthorizationResponse>
>;

/**
 * Verifies a JARM authorization response in signed, encrypted, or signed+encrypted mode.
 *
 * The function detects the response mode, performs decryption when needed, verifies
 * JWS signatures for signed payloads, and returns the parsed JARM body with metadata.
 *
 * @param options {@link VerifyJarmAuthorizationResponseOptions}
 * @returns Decryption and verification artifacts with parsed JARM payload.
 * @throws {Oauth2Error} If the response mode is invalid, decryption fails, or signature verification fails.
 */
export async function verifyJarmAuthorizationResponse(
  options: VerifyJarmAuthorizationResponseOptions,
) {
  const {
    authorizationRequestPayload,
    callbacks,
    jarmAuthorizationResponseJwt,
  } = options;

  const requestDataIsEncrypted = zCompactJwe.safeParse(
    jarmAuthorizationResponseJwt,
  ).success;
  const decryptedRequestData = requestDataIsEncrypted
    ? await decryptJarmAuthorizationResponseJwt({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt,
      })
    : { decryptionJwk: undefined, payload: jarmAuthorizationResponseJwt };

  const responseIsSigned = zCompactJwt.safeParse(
    decryptedRequestData.payload,
  ).success;

  if (!requestDataIsEncrypted && !responseIsSigned) {
    throw new Oauth2Error(
      "Jarm Auth Response must be either encrypted, signed, or signed and encrypted.",
    );
  }

  let jarmAuthorizationResponse:
    | JarmAuthorizationResponse
    | JarmAuthorizationResponseEncryptedOnly;

  if (responseIsSigned) {
    const { header: jwsProtectedHeader, payload: jwsPayload } = decodeJwt({
      headerSchema: z.object({ ...zJwtHeader.shape, kid: z.string() }),
      jwt: decryptedRequestData.payload,
    });

    const response = zJarmAuthorizationResponse.parse(jwsPayload);
    const jwtSigner = jwtSignerFromJwt({
      header: jwsProtectedHeader,
      payload: jwsPayload,
    });

    const verificationResult = await options.callbacks.verifyJwt(jwtSigner, {
      compact: decryptedRequestData.payload,
      header: jwsProtectedHeader,
      payload: jwsPayload,
    });

    if (!verificationResult.verified) {
      throw new Oauth2Error("Jarm Auth Response is not valid.");
    }

    jarmAuthorizationResponse = response;
  } else {
    const jsonRequestData = stringToJsonWithErrorHandling(
      decryptedRequestData.payload,
      "Unable to parse decrypted JARM JWE body to JSON",
    );
    jarmAuthorizationResponse =
      zJarmAuthorizationResponseEncryptedOnly.parse(jsonRequestData);
  }

  const type: JarmMode =
    requestDataIsEncrypted && responseIsSigned
      ? JarmMode.SignedEncrypted
      : requestDataIsEncrypted
        ? JarmMode.Encrypted
        : JarmMode.Signed;

  const issuer = jarmAuthorizationResponse.iss;
  return {
    decryptionJwk: decryptedRequestData.decryptionJwk,
    issuer,
    jarmAuthorizationResponse,
    type,
  };
}
