import { JsonWebKey } from "@openid-federation/core";

export type SignCallback = (options: {
  jwk: JsonWebKey;
  toBeSigned: Uint8Array;
}) => Promise<Uint8Array>;
