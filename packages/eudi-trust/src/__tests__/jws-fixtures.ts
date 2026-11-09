import type { VerifyJwtCallback } from "@pagopa/io-wallet-utils";

import { zJwk } from "@pagopa/io-wallet-utils";
import { KeyObject, createPublicKey, sign, verify } from "node:crypto";

const encode = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** Sign a compact ES256 JWS. */
export function signJws(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: KeyObject,
): string {
  const signingInput = `${encode({ alg: "ES256", ...header })}.${encode(payload)}`;
  const signature = sign("sha256", Buffer.from(signingInput), {
    dsaEncoding: "ieee-p1363",
    key,
  }).toString("base64url");
  return `${signingInput}.${signature}`;
}

export const toJwk = (key: KeyObject) =>
  zJwk.parse(key.export({ format: "jwk" }));

/** Verify an ES256 JWS with the `jwk` signer's public key. */
export const verifyJwtWithJwk: VerifyJwtCallback = (signer, jwt) => {
  if (signer.method !== "jwk") throw new Error("Expected a jwk signer");
  const [header, payload, signature = ""] = jwt.compact.split(".");
  const verified = verify(
    "sha256",
    Buffer.from(`${header}.${payload}`),
    {
      dsaEncoding: "ieee-p1363",
      key: createPublicKey({ format: "jwk", key: signer.publicJwk }),
    },
    Buffer.from(signature, "base64url"),
  );
  return verified ? { signerJwk: signer.publicJwk, verified } : { verified };
};
