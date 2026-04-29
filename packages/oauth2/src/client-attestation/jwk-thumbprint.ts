import {
  CallbackContext,
  HashAlgorithm,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";

import { Jwk } from "../common/jwk/z-jwk";

interface JwkThumbprintOptions {
  callbacks: Pick<CallbackContext, "hash">;
  dpopJwkPublic: Jwk;
}

export const calculateDpopJwkThumbprint = (
  options: JwkThumbprintOptions,
): Promise<string> =>
  calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: options.callbacks.hash,
    jwk: options.dpopJwkPublic,
  });
