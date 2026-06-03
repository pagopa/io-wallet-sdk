import {
  ValidationError,
  decodeUtf8String,
  encodeToBase64Url,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { HashAlgorithm, type HashCallback } from "../hash";
import { Jwk, zJwk } from "./z-jwk";

function createJwkThumbprintComponents(jwk: Jwk) {
  if (jwk.kty === "EC") {
    if (!jwk.crv || !jwk.x || !jwk.y) {
      throw new ValidationError(
        "Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.",
      );
    }

    return {
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    };
  }

  if (jwk.kty === "RSA") {
    if (!jwk.e || !jwk.n) {
      throw new ValidationError(
        "Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.",
      );
    }

    return {
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    };
  }

  if (jwk.kty === "oct") {
    if (!jwk.k) {
      throw new ValidationError(
        "Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.",
      );
    }

    return {
      k: jwk.k,
      kty: jwk.kty,
    };
  }

  throw new ValidationError(
    "Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.",
  );
}

export async function calculateJwkThumbprint(options: {
  hashAlgorithm: HashAlgorithm;
  hashCallback: HashCallback;
  jwk: Jwk;
}): Promise<string> {
  const parsedJwk = parseWithErrorHandling(
    zJwk,
    options.jwk,
    "Provided jwk does not match a supported jwk structure. Either the 'kty' is not supported, or required values are missing.",
  );

  const jwkThumbprintComponents = createJwkThumbprintComponents(parsedJwk);

  return encodeToBase64Url(
    await options.hashCallback(
      decodeUtf8String(JSON.stringify(jwkThumbprintComponents)),
      options.hashAlgorithm,
    ),
  );
}
