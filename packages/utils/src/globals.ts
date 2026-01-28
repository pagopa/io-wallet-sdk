import { HttpMethod } from "@openid4vc/utils";

export type FetchHeaders = globalThis.Headers;

export interface RequestLike {
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}
