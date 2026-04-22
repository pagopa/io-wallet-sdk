import { JsonWebKey } from "../jwk/jwk";

export type SignCallback = (options: {
  jwk: JsonWebKey;
  toBeSigned: Uint8Array;
}) => Promise<Uint8Array>;
