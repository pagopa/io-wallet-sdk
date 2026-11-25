/**
 * Semantic identifiers of ETSI EN 319 412-1 clauses 5.1.4 (legal person,
 * `organizationIdentifier`) and 5.1.3 (natural person, `serialNumber`):
 * identity type, country, "-" and identifier, or a national scheme ("XX:"
 * followed by the country).
 */
export const LEGAL_PERSON_IDENTIFIER =
  /^(?:(?:VAT|PSD|LEI|EOR|EXC)[A-Z]{2}|NTR[A-Z]{2}(?:\+[A-Z0-9]{1,3})?|[A-Z]{2}:[A-Z]{2})-.+$/;
export const NATURAL_PERSON_IDENTIFIER =
  /^(?:(?:PAS|IDC|PNO|TAX|TIN|EID)[A-Z]{2}|[A-Z]{2}:[A-Z]{2})-.+$/;
