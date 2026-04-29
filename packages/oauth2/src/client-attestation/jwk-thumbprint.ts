import { HashAlgorithm, calculateJwkThumbprint } from "@openid4vc/oauth2";

import { type BaseWalletAttestationOptions } from "./types";

export const calculateDpopJwkThumbprint = (
  options: Pick<BaseWalletAttestationOptions, "callbacks" | "dpopJwkPublic">,
) =>
  calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: options.callbacks.hash,
    jwk: options.dpopJwkPublic,
  });
