import { z } from "zod";

import {
  LEGAL_PERSON_IDENTIFIER,
  NATURAL_PERSON_IDENTIFIER,
} from "../x509/semantic-identifier";
import { isLegalPersonPolicy, isNaturalPersonPolicy } from "./policies";

const zWRPACFields = z.looseObject({
  isCA: z.literal(false, "A WRPAC must not be a CA certificate").optional(),
  keyUsage: z
    .array(z.string())
    .refine(
      (keyUsage) => keyUsage.includes("digitalSignature"),
      "keyUsage must include digitalSignature",
    )
    .optional(),
  policies: z.array(
    z.object({ cpsUris: z.array(z.string()), oid: z.string() }),
  ),
  subject: z.object({
    commonName: z.string().min(1),
    countryName: z.string().regex(/^[A-Z]{2}$/),
    givenName: z.string().min(1).optional(),
    organizationIdentifier: z.string().optional(),
    organizationName: z.string().min(1).optional(),
    serialNumber: z.string().optional(),
    surname: z.string().min(1).optional(),
  }),
  subjectAltNames: z.object({
    emails: z.array(z.string()),
    phoneNumbers: z.array(z.string()),
    uris: z.array(z.string()),
  }),
});

/** Constraints across WRPAC fields (ETSI TS 119 411-8 clause 6.6.1, ETSI TS 119 475 clause 5.1). */
function refineWRPAC(
  wrpac: z.infer<typeof zWRPACFields>,
  ctx: z.RefinementCtx,
): void {
  const { subject } = wrpac;
  const isLegalPerson = wrpac.policies.some(({ oid }) =>
    isLegalPersonPolicy(oid),
  );
  const isNaturalPerson = wrpac.policies.some(({ oid }) =>
    isNaturalPersonPolicy(oid),
  );

  // GEN-6.6.1-03
  if (isLegalPerson === isNaturalPerson) {
    ctx.addIssue({
      code: "custom",
      message: isLegalPerson
        ? "policies must not mix legal and natural person WRPAC policies"
        : "policies must include an ETSI TS 119 411-8 WRPAC policy",
      path: ["policies"],
    });
  }

  // GEN-6.6.1-05 and ETSI TS 119 475 Table 1
  if (isLegalPerson && !isNaturalPerson) {
    if (!subject.organizationName) {
      ctx.addIssue({
        code: "custom",
        message: "organizationName is required for a legal person",
        path: ["subject", "organizationName"],
      });
    }
    if (!LEGAL_PERSON_IDENTIFIER.test(subject.organizationIdentifier ?? "")) {
      ctx.addIssue({
        code: "custom",
        message:
          "organizationIdentifier must be a legal person semantic identifier (ETSI EN 319 412-1)",
        path: ["subject", "organizationIdentifier"],
      });
    }
  }

  // ETSI TS 119 475 Table 3
  if (isNaturalPerson && !isLegalPerson) {
    if (!subject.givenName || !subject.surname) {
      ctx.addIssue({
        code: "custom",
        message: "givenName and surname are required for a natural person",
        path: ["subject", "givenName"],
      });
    }
    if (!NATURAL_PERSON_IDENTIFIER.test(subject.serialNumber ?? "")) {
      ctx.addIssue({
        code: "custom",
        message:
          "serialNumber must be a natural person semantic identifier (ETSI EN 319 412-1)",
        path: ["subject", "serialNumber"],
      });
    }
  }

  // GEN-6.6.1-07
  const { emails, phoneNumbers, uris } = wrpac.subjectAltNames;
  if (emails.length + phoneNumbers.length + uris.length === 0) {
    ctx.addIssue({
      code: "custom",
      message: "subjectAltNames must include a URI, an email or a phone number",
      path: ["subjectAltNames"],
    });
  }
}

/**
 * WRPAC certificate content (ETSI TS 119 411-8 clause 6.6.1), checked on the
 * metadata returned by `getX509CertificateMetadata`.
 */
export type WRPAC = z.infer<typeof zWRPAC>;
export const zWRPAC = zWRPACFields.superRefine(refineWRPAC);
