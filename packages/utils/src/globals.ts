import { HttpMethod } from "./validation";

export type Fetch = typeof fetch;
export type FetchHeaders = globalThis.Headers;

export interface RequestLike {
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}
