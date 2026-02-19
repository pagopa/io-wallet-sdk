import { FetchHeaders, HttpMethod } from "@pagopa/io-wallet-utils";
import z from "zod";

export const zAlgValueNotNone = z
  .string()
  .refine((alg) => alg !== "none", { message: `alg value may not be 'none'` });

export interface RequestLike {
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}
