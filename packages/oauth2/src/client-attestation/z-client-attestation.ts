import { zJwk, zJwtHeader, zJwtPayload } from "@openid4vc/oauth2";
import { zInteger } from "@openid4vc/utils";
import z from "zod";

export const zOauthClientAttestationHeader = z.literal(
  "OAuth-Client-Attestation",
);

export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value;

export const zOauthClientAttestationPopHeader = z.literal(
  "OAuth-Client-Attestation-PoP",
);

export const oauthClientAttestationPopHeader =
  zOauthClientAttestationPopHeader.value;

export const zClientAttestationJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    trust_chain: z.array(z.string()),
    typ: z.literal("oauth-client-attestation+jwt"),
  })
  .passthrough();

export type ClientAttestationJwtHeader = z.infer<
  typeof zClientAttestationJwtHeader
>;

export const zClientAttestationJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    // JSON String asserting the authentication level of the Wallet and the key as asserted in the cnf claim.
    aal: z.string(),
    cnf: z
      .object({
        jwk: zJwk,
      })
      .passthrough(),
    exp: zInteger,
    iss: z.string(),
    sub: z.string(),

    wallet_link: z.string().url().optional(),
    // OID4VCI Wallet Attestation Extensions
    wallet_name: z.string().optional(),
  })
  .passthrough();
export type ClientAttestationJwtPayload = z.infer<
  typeof zClientAttestationJwtPayload
>;
