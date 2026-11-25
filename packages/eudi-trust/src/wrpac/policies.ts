/**
 * WRPAC certificate policies of ETSI TS 119 411-8 clause 5.3.
 */
export const WRPAC_POLICIES = {
  /** NCP-l-eudiwrp: normalized, legal person. */
  NCP_LEGAL: "0.4.0.194118.1.2",
  /** NCP-n-eudiwrp: normalized, natural person. */
  NCP_NATURAL: "0.4.0.194118.1.1",
  /** QCP-l-eudiwrp: qualified, legal person. */
  QCP_LEGAL: "0.4.0.194118.1.4",
  /** QCP-n-eudiwrp: qualified, natural person. */
  QCP_NATURAL: "0.4.0.194118.1.3",
} as const;

const LEGAL_PERSON_POLICIES: string[] = [
  WRPAC_POLICIES.NCP_LEGAL,
  WRPAC_POLICIES.QCP_LEGAL,
];
const NATURAL_PERSON_POLICIES: string[] = [
  WRPAC_POLICIES.NCP_NATURAL,
  WRPAC_POLICIES.QCP_NATURAL,
];

export const isLegalPersonPolicy = (oid: string) =>
  LEGAL_PERSON_POLICIES.includes(oid);

export const isNaturalPersonPolicy = (oid: string) =>
  NATURAL_PERSON_POLICIES.includes(oid);
