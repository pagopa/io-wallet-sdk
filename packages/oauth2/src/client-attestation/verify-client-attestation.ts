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

export interface VerifyClientAttestationOptions {
  clientAttestationJwt: string;

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

export async function verifyClientAttestation(
  options: VerifyClientAttestationOptions,
  authorizationServerMetadata: AuthorizationServerMetadata,
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">,
  dpopJwkThumbprint?: string,
  now?: Date,
  requestClientId?: string,
) {
  if (!options.clientAttestationJwt || !options.clientAttestationPopJwt) {
    throw new Oauth2Error(
      `Missing required client attestation parameters in the request. Make sure to provide the '${oauthClientAttestationHeader}' and '${oauthClientAttestationPopHeader}' header values.`,
    );
  }

  const clientAttestation = await verifyClientAttestationJwt({
    callbacks,
    clientAttestationJwt: options.clientAttestationJwt,
    now,
  });

  const clientAttestationPop = await verifyClientAttestationPopJwt({
    authorizationServer: authorizationServerMetadata.issuer,
    callbacks: callbacks,
    clientAttestationPopJwt: options.clientAttestationPopJwt,
    clientAttestationPublicJwk: clientAttestation.payload.cnf.jwk,
    now,
  });

  if (requestClientId && requestClientId !== clientAttestation.payload.sub) {
    // Ensure the client id matches with the client id provided in the authorization request
    throw new Oauth2Error(
      `The client_id '${requestClientId}' in the request does not match the client id '${clientAttestation.payload.sub}' in the client attestation`,
    );
  }

  if (options.ensureConfirmationKeyMatchesDpopKey && dpopJwkThumbprint) {
    const clientAttestationJkt = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: clientAttestation.payload.cnf.jwk,
    });

    if (clientAttestationJkt !== dpopJwkThumbprint) {
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
