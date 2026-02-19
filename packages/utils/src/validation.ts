import z from "zod";

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
