import { FetchHeaders, HttpMethod } from "@pagopa/io-wallet-utils";
import z from "zod";

export const zTrustChain = z.tuple([z.string()], z.string());
export type TrustChain = z.infer<typeof zTrustChain>;

export const zCertificateChain = z.array(z.string()).nonempty();
export type CertificateChain = z.infer<typeof zCertificateChain>;

export const zAlgValueNotNone = z
  .string()
  .refine((alg) => alg !== "none", { message: `alg value may not be 'none'` });

export interface RequestLike {
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}
