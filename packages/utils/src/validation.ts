import z from "zod";

/**
 * For the moment, these are all the supported algorithms in both
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/algorithms.html#cryptographic-algorithms|v1.3.3} and
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/algorithms.html#cryptographic-algorithms|v1.0.2},
 * and in both specifications the `alg` field MUST be one of those values.
 */
export const zItwSupportedSignatureAlg = z.enum([
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "PS384",
  "PS512",
]);
export type ItwSupportedSignatureAlg = z.infer<
  typeof zItwSupportedSignatureAlg
>;

export const zHttpMethod = z.enum([
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "TRACE",
  "CONNECT",
  "PATCH",
]);
export type HttpMethod = z.infer<typeof zHttpMethod>;
