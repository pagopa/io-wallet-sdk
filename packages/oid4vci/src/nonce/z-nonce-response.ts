import * as z from "zod";

/**
 * Parser for runtime validation of a Nonce Response as defined in OID4VCI Draft 15 section 7 subsection 7.2.
 */
export const zNonceResponse = z.object({
  c_nonce: z.string(),
});

/**
 * TypeScript definition for the NonceResponse parser.
 */
export type NonceResponse = z.infer<typeof zNonceResponse>;
