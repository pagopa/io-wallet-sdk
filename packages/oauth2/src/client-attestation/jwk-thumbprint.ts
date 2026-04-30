import {
  CallbackContext,
  HashAlgorithm,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";

import { Jwk } from "../common/jwk/z-jwk";
import { ClientAttestationError } from "../errors";

const SUPPORTED_KTY = ["RSA", "EC"] as const;

interface JwkThumbprintOptions {
  callbacks: Pick<CallbackContext, "hash">;
  dpopJwkPublic: Jwk;
}

export const calculateDpopJwkThumbprint = (
  options: JwkThumbprintOptions,
): Promise<string> => {
  if (
    !SUPPORTED_KTY.includes(
      options.dpopJwkPublic.kty as (typeof SUPPORTED_KTY)[number],
    )
  ) {
    throw new ClientAttestationError(
      `Unsupported JWK key type "${options.dpopJwkPublic.kty}" for thumbprint computation. Supported types: ${SUPPORTED_KTY.join(", ")}.`,
    );
  }

  return calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: options.callbacks.hash,
    jwk: options.dpopJwkPublic,
  });
};
