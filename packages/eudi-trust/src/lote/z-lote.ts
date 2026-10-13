/**
 * LoTE Zod Schemas
 *
 * Zod schemas for ETSI TS 119 602 (LoTE - List of Trusted Entities) format.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 */

import { HashAlgorithm } from "@pagopa/io-wallet-utils";
import { z } from "zod";

// ============================================================================
// Localized Value Schemas
// ============================================================================

export const zLocalizedString = z.object({
  lang: z.string().min(1),
  value: z.string().min(1),
});

export const zLocalizedURI = z.object({
  lang: z.string().min(1),
  uriValue: z.url(),
});

// ============================================================================
// Address Schemas
// ============================================================================

export const zPostalAddress = z.object({
  Country: z.string().length(2),
  Locality: z.string(),
  PostalCode: z.string(),
  StateOrProvince: z.string().optional(),
  StreetAddress: z.string(),
  lang: z.string().min(1),
});

export const zSchemeOperatorAddress = z.object({
  SchemeOperatorElectronicAddress: z.array(zLocalizedURI),
  SchemeOperatorPostalAddress: z.array(zPostalAddress),
});

export const zTrustedEntityAddress = z.object({
  TEElectronicAddress: z.array(zLocalizedURI),
  TEPostalAddress: z.array(zPostalAddress),
});

// ============================================================================
// Digital Identity Schemas
// ============================================================================

export const zPkiObject = z.object({
  encoding: z.string().optional(),
  specRef: z.string().optional(),
  val: z.string().min(1),
});

export const zX509CertificateRef = zPkiObject.extend({
  encoding: z.literal("urn:ietf:params:tls-cert-type:x509").optional(),
  specRef: z.literal("RFC5280").optional(),
});

export const zJWKPublicKey = z.looseObject({
  alg: z.string().optional(),
  kid: z.string().optional(),
  kty: z.enum(["RSA", "EC", "OKP"]),
  use: z.enum(["sig", "enc"]).optional(),
});

export type ServiceDigitalIdentity = z.infer<typeof zServiceDigitalIdentity>;
export const zServiceDigitalIdentity = z
  .object({
    OtherIds: z.array(z.string()).optional(),
    PublicKeyValues: z.array(zJWKPublicKey).optional(),
    X509Certificates: z.array(zX509CertificateRef).optional(),
    X509SKIs: z.array(z.string()).optional(),
    X509SubjectNames: z.array(z.string()).optional(),
  })
  .refine(
    (id) =>
      (id.X509Certificates && id.X509Certificates.length > 0) ||
      (id.X509SubjectNames && id.X509SubjectNames.length > 0) ||
      (id.PublicKeyValues && id.PublicKeyValues.length > 0) ||
      (id.X509SKIs && id.X509SKIs.length > 0) ||
      (id.OtherIds && id.OtherIds.length > 0),
    { message: "At least one digital identity type must be provided" },
  );

// ============================================================================
// Service Schemas
// ============================================================================

export const zServiceSupplyPoint = z.object({
  ServiceType: z.string().optional(),
  uriValue: z.url(),
});

export type ServiceInformation = z.infer<typeof zServiceInformation>;
export const zServiceInformation = z.object({
  SchemeServiceDefinitionURI: z.array(zLocalizedURI).optional(),
  ServiceDefinitionURI: z.array(zLocalizedURI).optional(),
  ServiceDigitalIdentity: zServiceDigitalIdentity,
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
  ServiceName: z.array(zLocalizedString).min(1),
  ServiceStatus: z.url().optional(),
  ServiceSupplyPoints: z.array(zServiceSupplyPoint).optional(),
  ServiceTypeIdentifier: z.url().optional(),
  StatusStartingTime: z.iso.datetime().optional(),
});

export type ServiceHistoryInstance = z.infer<typeof zServiceHistoryInstance>;
export const zServiceHistoryInstance = z.object({
  ServiceDigitalIdentity: zServiceDigitalIdentity,
  ServiceInformationExtensions: z.array(z.unknown()).optional(),
  ServiceName: z.array(zLocalizedString).min(1),
  ServiceStatus: z.url(),
  ServiceTypeIdentifier: z.url().optional(),
  StatusStartingTime: z.iso.datetime(),
});

export type TrustedEntityService = z.infer<typeof zTrustedEntityService>;
export const zTrustedEntityService = z.object({
  ServiceHistory: z.array(zServiceHistoryInstance).optional(),
  ServiceInformation: zServiceInformation,
});

// ============================================================================
// Trusted Entity Schemas
// ============================================================================

export type TrustedEntityInformation = z.infer<
  typeof zTrustedEntityInformation
>;
export const zTrustedEntityInformation = z.object({
  TEAddress: zTrustedEntityAddress,
  TEInformationExtensions: z.array(z.unknown()).optional(),
  TEInformationURI: z.array(zLocalizedURI).optional(),
  TEName: z.array(zLocalizedString).min(1),
  TETradeName: z.array(zLocalizedString).optional(),
});

export type TrustedEntity = z.infer<typeof zTrustedEntity>;
export const zTrustedEntity = z.object({
  TrustedEntityInformation: zTrustedEntityInformation,
  TrustedEntityServices: z.array(zTrustedEntityService).min(1),
});

// ============================================================================
// List and Scheme Information Schemas
// ============================================================================

export const zPolicyOrLegalNotice = z.object({
  LoTELegalNotice: zLocalizedString.optional(),
  LoTEPolicy: zLocalizedURI.optional(),
});

export type LoTEQualifier = z.infer<typeof zLoTEQualifier>;
export const zLoTEQualifier = z.object({
  LoTEType: z.url(),
  MimeType: z.string().min(1),
  SchemeOperatorName: z.array(zLocalizedString).min(1),
  SchemeTerritory: z.string().length(2).optional(),
  SchemeTypeCommunityRules: z.array(zLocalizedURI).optional(),
});

export type OtherLoTEPointer = z.infer<typeof zOtherLoTEPointer>;
export const zOtherLoTEPointer = z.object({
  LoTELocation: z.url(),
  LoTEQualifiers: z.array(zLoTEQualifier).min(1),
  ServiceDigitalIdentities: z.array(zServiceDigitalIdentity).min(1),
});

export type ListAndSchemeInformation = z.infer<
  typeof zListAndSchemeInformation
>;
export const zListAndSchemeInformation = z.object({
  DistributionPoints: z.array(z.url()).optional(),
  HistoricalInformationPeriod: z.number().optional(),
  ListIssueDateTime: z.iso.datetime(),
  LoTESequenceNumber: z.number().int(),
  LoTEType: z.url().optional(),
  LoTEVersionIdentifier: z.number().int(),
  NextUpdate: z.iso.datetime(),
  PointersToOtherLoTE: z.array(zOtherLoTEPointer).optional(),
  PolicyOrLegalNotice: z.array(zPolicyOrLegalNotice).optional(),
  SchemeExtensions: z.array(z.unknown()).optional(),
  SchemeInformationURI: z.array(zLocalizedURI).optional(),
  SchemeName: z.array(zLocalizedString).optional(),
  SchemeOperatorAddress: zSchemeOperatorAddress.optional(),
  SchemeOperatorName: z.array(zLocalizedString).min(1),
  SchemeTerritory: z.string().length(2).optional(),
  SchemeTypeCommunityRules: z.array(zLocalizedURI).optional(),
  StatusDeterminationApproach: z.url().optional(),
});

// ============================================================================
// LoTE Root Schemas
// ============================================================================

export type LoTE = z.infer<typeof zLoTE>;
export const zLoTE = z.object({
  ListAndSchemeInformation: zListAndSchemeInformation,
  TrustedEntitiesList: z.array(zTrustedEntity),
});

export type LoTEDocument = z.infer<typeof zLoTEDocument>;
export const zLoTEDocument = z.object({
  LoTE: zLoTE,
});

/**
 * Protected header of a compact JAdES Baseline B signature (ETSI TS 119 182-1),
 * as mandated for LoTEs by ETSI TS 119 602 clause 6.8.0 and Annexes D-I.
 *
 * The LoTE payload is always attached and base64url-encoded, so detached
 * signatures (`sigD`) and unencoded payloads (`b64`) are rejected; `iat`
 * replaces the legacy `sigT` signing time.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf
 */
export type LoTEJwtHeader = z.infer<typeof zLoTEJwtHeader>;
export const zLoTEJwtHeader = z.object({
  alg: z
    .string()
    .refine(
      (alg) => alg !== "none" && !alg.startsWith("HS"),
      "alg must be an asymmetric signature algorithm",
    ),
  b64: z.never().optional(),
  cty: z.string(),
  iat: z.number().int(),
  kid: z.string(),
  sigD: z.never().optional(),
  sigT: z.never().optional(),
  typ: z.string(),
  x5c: z.tuple([z.string()], z.string()),
  "x5t#o": z
    .object({
      digAlg: z.enum(HashAlgorithm),
      digVal: z.string(),
    })
    .optional(),
});
