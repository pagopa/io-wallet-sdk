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
  zEncryptedJarmHeader,
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
    headerSchema: zEncryptedJarmHeader,
    jwt: jarmAuthorizationResponseJwt,
  });

  const jwks = authorizationRequestPayload.client_metadata?.jwks;

  if (jwks) {
    encryptionJwk = extractEncryptionJwkFromJwks(jwks, { kid: header.kid });
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
  /**
   * Current time used for temporal claim validation (`exp`, `nbf`).
   * Defaults to current date-time when omitted.
   */
  now?: Date;
}

/**
 * Verified JARM authorization response data returned by {@link verifyJarmAuthorizationResponse}.
 */
export interface VerifyJarmAuthorizationResponseResult {
  /**
   * JWK used for decryption when the response is encrypted, or `undefined` if the response was not encrypted.
   */
  decryptionJwk: Jwk | undefined;
  /**
   * The `iss` claim from the JARM response, representing the issuer of the response.
   */
  issuer: string | undefined;
  /**
   * The parsed JARM authorization response body, containing claims like `iss`, `aud`, `exp`, etc.
   */
  jarmAuthorizationResponse:
    | JarmAuthorizationResponse
    | JarmAuthorizationResponseEncryptedOnly;
  /**
   * Detected JARM processing mode indicating whether the response was signed, encrypted, or both.
   */
  type: JarmMode;
}

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
      errorMessagePrefix: "Error decoding JARM authorization response JWT:",
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

    const expectedAudience = authorizationRequestPayload.client_id;
    const expectedIssuer = authorizationRequestPayload.iss;
    if (response.aud !== expectedAudience) {
      throw new Oauth2Error(
        `Jarm Auth Response contains 'aud' value '${response.aud}', but expected '${expectedAudience}'.`,
      );
    }

    if (response.iss !== expectedIssuer) {
      throw new Oauth2Error(
        `Jarm Auth Response contains 'iss' value '${response.iss}', but expected '${expectedIssuer}'.`,
      );
    }

    const now = options.now ?? new Date();
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (response.exp < nowSeconds) {
      throw new Oauth2Error("Jarm Auth Response has expired.");
    }

    if (response.nbf !== undefined && response.nbf > nowSeconds) {
      throw new Oauth2Error("Jarm Auth Response is not active yet.");
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
