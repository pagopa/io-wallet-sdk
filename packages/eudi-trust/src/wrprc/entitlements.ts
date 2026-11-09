/**
 * Entitlement identifiers of ETSI TS 119 475 Annex A.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

/** `id-etsi-wrpa-entitlement` OID arc (Annex A.1). */
export const ETSI_WRPA_ENTITLEMENT_ARC = "0.4.0.19475.1";

/** WRP entitlements (Annex A.2). */
export const WRP_ENTITLEMENTS = {
  ESIG_ESEAL_CREATION_PROVIDER:
    "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider",
  NON_Q_EAA_PROVIDER:
    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider",
  PID_PROVIDER: "https://uri.etsi.org/19475/Entitlement/PID_Provider",
  PUB_EAA_PROVIDER: "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider",
  QCERT_FOR_ESEAL_PROVIDER:
    "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider",
  QCERT_FOR_ESIG_PROVIDER:
    "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider",
  QEAA_PROVIDER: "https://uri.etsi.org/19475/Entitlement/QEAA_Provider",
  RQSEALCDS_PROVIDER:
    "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider",
  RQSIGCDS_PROVIDER: "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider",
  SERVICE_PROVIDER: "https://uri.etsi.org/19475/Entitlement/Service_Provider",
} as const;

/** WRP entitlements in OID form (`id-etsi-wrpa-entitlement` 1-10). */
export const WRP_ENTITLEMENT_OIDS = {
  ESIG_ESEAL_CREATION_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.10`,
  NON_Q_EAA_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.3`,
  PID_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.5`,
  PUB_EAA_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.4`,
  QCERT_FOR_ESEAL_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.6`,
  QCERT_FOR_ESIG_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.7`,
  QEAA_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.2`,
  RQSEALCDS_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.8`,
  RQSIGCDS_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.9`,
  SERVICE_PROVIDER: `${ETSI_WRPA_ENTITLEMENT_ARC}.1`,
} as const satisfies Record<keyof typeof WRP_ENTITLEMENTS, string>;

export type WRPEntitlementKey = keyof typeof WRP_ENTITLEMENTS;
export type WRPEntitlement = (typeof WRP_ENTITLEMENTS)[WRPEntitlementKey];

/** All WRP entitlements, in URI and OID form. */
export const ALL_ENTITLEMENTS: string[] = [
  ...Object.values(WRP_ENTITLEMENTS),
  ...Object.values(WRP_ENTITLEMENT_OIDS),
];

/** Payment Service Provider sub-entitlements (Annex A.3.1). */
export const PSP_SUB_ENTITLEMENTS = {
  ACCOUNT_INFORMATION: "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ai",
  ACCOUNT_SERVICING: "https://uri.etsi.org/19475/SubEntitlement/psp/psp-as",
  CARD_BASED: "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ic",
  PAYMENT_INITIATION: "https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi",
  UNSPECIFIED: "https://uri.etsi.org/19475/SubEntitlement/psp/unspecified",
} as const;

export const ALL_PSP_SUB_ENTITLEMENTS: string[] =
  Object.values(PSP_SUB_ENTITLEMENTS);

/** Whether `entitlement` is a WRP entitlement, in URI or OID form. */
export function isValidEntitlement(entitlement: string): boolean {
  return ALL_ENTITLEMENTS.includes(entitlement);
}

export function isPSPSubEntitlement(entitlement: string): boolean {
  return ALL_PSP_SUB_ENTITLEMENTS.includes(entitlement);
}
