import {
  AuthorizationServerMetadata,
  CallbackContext,
  HashAlgorithm,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";

import { Oauth2Error } from "../errors";
import { verifyClientAttestationJwt } from "./client-attestation";
import { verifyClientAttestationPopJwt } from "./client-attestation-pop";
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./z-client-attestation";

export interface ClientAttestationOptions {
  /**
   * The client attestation JWT provided in the request.
   */
  clientAttestationJwt: string;

  /**
   * The client attestation DPoP JWT provided in the request.
   */
  clientAttestationPopJwt: string;

  /**
   * Whether to ensure that the key used in client attestation confirmation
   * is the same key used for DPoP. This only has effect if both DPoP and client
   * attestations are present.
   *
   * @default false
   */
  ensureConfirmationKeyMatchesDpopKey?: boolean;
}

export interface VerifyClientAttestationOptions {
  /**
   * The authorization server metadata.
   */
  authorizationServerMetadata: AuthorizationServerMetadata;

  /**
   * Callbacks for hashing and JWT verification.
   */
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;

  /**
   * The client attestation options.
   */
  clientAttestation: ClientAttestationOptions;

  /**
   * The DPoP JWK thumbprint value, if DPoP is being used in the request.
   */
  dpopJwkThumbprint?: string;

  /**
   * The current time to use when verifying the JWTs. If not provided, the current system time will be used.
   */
  now?: Date;

  /**
   * The client id provided in the authorization request, if any.
   */
  requestClientId?: string;
}

export async function verifyClientAttestation(
  options: VerifyClientAttestationOptions,
) {
  if (
    !options.clientAttestation.clientAttestationJwt ||
    !options.clientAttestation.clientAttestationPopJwt
  ) {
    throw new Oauth2Error(
      `Missing required client attestation parameters in the request. Make sure to provide the '${oauthClientAttestationHeader}' and '${oauthClientAttestationPopHeader}' header values.`,
    );
  }

  const clientAttestation = await verifyClientAttestationJwt({
    callbacks: options.callbacks,
    clientAttestationJwt: options.clientAttestation.clientAttestationJwt,
    now: options.now,
  });

  const clientAttestationPop = await verifyClientAttestationPopJwt({
    authorizationServer: options.authorizationServerMetadata.issuer,
    callbacks: options.callbacks,
    clientAttestationPopJwt: options.clientAttestation.clientAttestationPopJwt,
    clientAttestationPublicJwk: clientAttestation.payload.cnf.jwk,
    now: options.now,
  });

  if (
    options.requestClientId &&
    options.requestClientId !== clientAttestation.payload.sub
  ) {
    // Ensure the client id matches with the client id provided in the authorization request
    throw new Oauth2Error(
      `The client_id '${options.requestClientId}' in the request does not match the client id '${clientAttestation.payload.sub}' in the client attestation`,
    );
  }

  if (
    options.clientAttestation.ensureConfirmationKeyMatchesDpopKey &&
    options.dpopJwkThumbprint
  ) {
    const clientAttestationJkt = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: options.callbacks.hash,
      jwk: clientAttestation.payload.cnf.jwk,
    });

    if (clientAttestationJkt !== options.dpopJwkThumbprint) {
      throw new Oauth2Error(
        "Expected the DPoP JWK thumbprint value to match the JWK thumbprint of the client attestation confirmation JWK. Ensure both DPoP and client attestation use the same key.",
      );
    }
  }

  return {
    clientAttestation,
    clientAttestationPop,
  };
}
