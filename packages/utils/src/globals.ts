import { HttpMethod } from "./validation";

export type FetchHeaders = globalThis.Headers;

export interface RequestLike {
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}
