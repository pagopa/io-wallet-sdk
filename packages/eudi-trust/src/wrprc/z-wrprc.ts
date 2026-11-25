import { z } from "zod";

import { zJAdESHeader } from "../jades/z-jades";
import {
  LEGAL_PERSON_IDENTIFIER,
  NATURAL_PERSON_IDENTIFIER,
} from "../x509/semantic-identifier";
import { isPSPSubEntitlement, isValidEntitlement } from "./entitlements";

/**
 * WRPRC JWT header (ETSI TS 119 475 clause 5.2.2, Table 5): a JAdES B-B header
 * as required by GEN-5.2.1-04, where `iat` is the claimed signing time.
 */
export type WRPRCJwtHeader = z.infer<typeof zWRPRCJwtHeader>;
export const zWRPRCJwtHeader = zJAdESHeader.extend({
  typ: z.literal("rc-wrp+jwt"),
});

/** ETSI TS 119 475 Annex B.2.6 MultiLangString. */
const zMultiLangString = z.object({
  lang: z.string().min(1),
  value: z.string().min(1),
});

/**
 * ETSI TS 119 475 Annex B.2.10 Claim.
 *
 * `path` follows the DCQL claims path pointer.
 */
const zCredentialClaim = z.object({
  path: z
    .array(z.union([z.string(), z.number().int().nonnegative(), z.null()]))
    .min(1),
  values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional(),
});

/** ETSI TS 119 475 Annex B.2.9 Credential, as used in Tables 8 and 9. */
const zCredential = z.object({
  claim: z.array(zCredentialClaim).min(1).optional(),
  format: z.string().min(1),
  meta: z.record(z.string(), z.unknown()),
});

const MAX_VALIDITY_IN_MONTHS = 12;

const zWRPRCPayloadClaims = z.looseObject({
  certificate_policy: z.url().optional(),
  country: z.string().regex(/^[A-Z]{2}$/),
  credentials: z.array(zCredential).optional(),
  entitlements: z
    .array(
      z
        .string()
        .refine(
          (entitlement) =>
            isValidEntitlement(entitlement) || isPSPSubEntitlement(entitlement),
          "Unknown entitlement (ETSI TS 119 475 Annex A)",
        ),
    )
    .min(1),
  exp: z.number().int().optional(),
  iat: z.number().int(),
  info_uri: z.url().optional(),
  intended_use_id: z.string().min(1).optional(),
  /** ETSI TS 119 475 Table 10. */
  intermediary: z
    .object({ sname: z.string().min(1), sub: z.string().min(1) })
    .optional(),
  name: z.string().min(1),
  policy_id: z.array(z.string().min(1)).optional(),
  privacy_policy: z.url().optional(),
  provides_attestations: z.array(zCredential.omit({ claim: true })).optional(),
  public_body: z.boolean().optional(),
  purpose: z.array(zMultiLangString).optional(),
  registry_uri: z.url(),
  srv_description: z.array(zMultiLangString).optional(),
  status: z.object({
    status_list: z.object({
      idx: z.number().int().nonnegative(),
      uri: z.url(),
    }),
  }),
  sub: z.string().min(1),
  sub_fn: z.string().min(1).optional(),
  sub_gn: z.string().min(1).optional(),
  sub_ln: z.string().min(1).optional(),
  supervisory_authority: z
    .object({
      email: z.email().optional(),
      phone: z.string().min(1).optional(),
      uri: z.url().optional(),
    })
    .optional(),
  support_uri: z.union([z.url(), z.email()]).optional(),
});

/** Constraints across WRPRC payload claims (ETSI TS 119 475 clause 5.2.4). */
function WRPRCPayloadRefiner(
  payload: z.infer<typeof zWRPRCPayloadClaims>,
  ctx: z.RefinementCtx,
) {
  const isLegalPerson = payload.sub_ln !== undefined;
  if (!isLegalPerson && (!payload.sub_gn || !payload.sub_fn)) {
    ctx.addIssue({
      code: "custom",
      message:
        "sub_ln (legal person), or sub_gn and sub_fn (natural person), are required",
      path: ["sub_ln"],
    });
  }

  // GEN-5.1.3-03 and GEN-5.1.5-03
  const identifier = isLegalPerson
    ? LEGAL_PERSON_IDENTIFIER
    : NATURAL_PERSON_IDENTIFIER;
  if (!identifier.test(payload.sub)) {
    ctx.addIssue({
      code: "custom",
      message: `sub must be a ${isLegalPerson ? "legal" : "natural"} person semantic identifier (ETSI EN 319 412-1)`,
      path: ["sub"],
    });
  }

  // GEN-5.2.4-03
  if (!payload.entitlements.some(isValidEntitlement)) {
    ctx.addIssue({
      code: "custom",
      message: "entitlements must include an Annex A.2 entitlement",
      path: ["entitlements"],
    });
  }

  // GEN-5.2.4-08
  if (payload.exp !== undefined) {
    const maxExp = new Date(payload.iat * 1000);
    maxExp.setUTCMonth(maxExp.getUTCMonth() + MAX_VALIDITY_IN_MONTHS);
    if (payload.exp <= payload.iat || payload.exp * 1000 > maxExp.getTime()) {
      ctx.addIssue({
        code: "custom",
        message: "exp must be after iat and at most 12 months later",
        path: ["exp"],
      });
    }
  }
}

/** WRPRC payload (ETSI TS 119 475 clause 5.2.4). */
export type WRPRCPayload = z.infer<typeof zWRPRCPayload>;
export const zWRPRCPayload =
  zWRPRCPayloadClaims.superRefine(WRPRCPayloadRefiner);
