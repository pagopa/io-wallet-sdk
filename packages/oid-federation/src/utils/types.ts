import { JWK } from "../jwk";

export type SignCallback = (options: {
  jwk: JWK;
  toBeSigned: Uint8Array;
}) => Promise<Uint8Array>;
