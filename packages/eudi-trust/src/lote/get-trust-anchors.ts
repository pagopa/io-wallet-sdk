import { LoTEError } from "../errors";
import {
  base64ToKeyIdentifier,
  normalizeDistinguishedName,
  normalizeKeyIdentifier,
} from "../x509/certificate";
import { LOTE_TYPES, LoTEProfile, PUB_EAA_SERVICE_STATUS } from "./constants";
import { LoTE, TrustedEntityService } from "./z-lote";

export interface GetTrustAnchorsOptions {
  /**
   * Authority Key Identifier (extension OID 2.5.29.35)
   * of the last certificate of the chain in hexadecimal format.
   */
  authorityKeyIdentifier?: string;
  /**
   * Issuer Distinguished Name of the last certificate of the chain.
   */
  issuerName?: string;
  /**
   * `organizationIdentifier` of the issuer of the last certificate of the chain.
   */
  issuerOrganizationIdentifier?: string;
  /**
   * A LoTE authenticated with `validateLoTE`.
   */
  lote: LoTE;
  profile: LoTEProfile;
  /**
   * E.g. `http://uri.etsi.org/19602/SvcType/WRPAC/Issuance` (ETSI TS 119 602 Annexes D-I).
   */
  serviceTypeIdentifier: string;
}

/**
 * Retrieves the candidate Trust Anchors (DER certificates encoded in base64)
 * that a LoTE publishes for a given service type, as per the IT-Wallet EUDIW
 * authentication, based on ETSI TS 119 602.
 *
 * Only active services contribute. The candidates are narrowed by the first of these
 * criteria matching some of them: the Authority Key Identifier against `X509SKIs`,
 * the issuer name against `X509SubjectNames`,
 * and finally the issuer organization identifier against the entity trade name.
 *
 * @returns The candidate Trust Anchors.
 * @throws {LoTEError} if the LoTE does not match the expected profile.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-authentication
 */
export function getTrustAnchors({
  authorityKeyIdentifier,
  issuerName,
  issuerOrganizationIdentifier,
  lote,
  profile,
  serviceTypeIdentifier,
}: GetTrustAnchorsOptions): string[] {
  if (lote.ListAndSchemeInformation.LoTEType !== LOTE_TYPES[profile]) {
    throw new LoTEError(`LoTE is not of type ${LOTE_TYPES[profile]}`, {
      code: "UNEXPECTED_LoTE_TYPE",
    });
  }

  if (!lote.TrustedEntitiesList) {
    return [];
  }

  const isRequestedServiceType = ({
    ServiceInformation,
  }: TrustedEntityService) =>
    ServiceInformation.ServiceTypeIdentifier === serviceTypeIdentifier &&
    (ServiceInformation.ServiceStatus === undefined ||
      ServiceInformation.ServiceStatus === PUB_EAA_SERVICE_STATUS.notified);

  const services = lote.TrustedEntitiesList.flatMap(
    (entity) => entity.TrustedEntityServices,
  ).filter(isRequestedServiceType);

  // 1. Find certificates that match `X509SKIs` (Authority Key Identifier)
  if (authorityKeyIdentifier) {
    const expected = normalizeKeyIdentifier(authorityKeyIdentifier);
    return getServiceCertificates(
      services.filter(({ ServiceInformation }) =>
        ServiceInformation.ServiceDigitalIdentity.X509SKIs?.some(
          (ski) => base64ToKeyIdentifier(ski) === expected,
        ),
      ),
    );
  }

  // 2. Find certificates that match the Issuer's Distinguished Name
  if (issuerName) {
    const expected = normalizeDistinguishedName(issuerName);
    return getServiceCertificates(
      services.filter(({ ServiceInformation }) =>
        ServiceInformation.ServiceDigitalIdentity.X509SubjectNames?.some(
          (name) => normalizeDistinguishedName(name) === expected,
        ),
      ),
    );
  }

  // 3. Find certificates that match the registration identifier of the entity
  // found in `TETradeName` (ETSI EN 319 412-1 clause 5.1.4, ETSI TS 119 602 Annex F)
  if (issuerOrganizationIdentifier) {
    return getServiceCertificates(
      lote.TrustedEntitiesList.filter((entity) =>
        entity.TrustedEntityInformation.TETradeName?.some(
          ({ value }) => value === issuerOrganizationIdentifier,
        ),
      )
        .flatMap((entity) => entity.TrustedEntityServices)
        .filter(isRequestedServiceType),
    );
  }

  // 4. Get all certificates if no filtering parameters are provided
  return getServiceCertificates(
    lote.TrustedEntitiesList.flatMap(
      (entity) => entity.TrustedEntityServices,
    ).filter(isRequestedServiceType),
  );
}

/**
 * Extract and flatten the X.509 certificates of the provided services.
 */
const getServiceCertificates = (services: TrustedEntityService[]) =>
  services
    .flatMap(
      ({ ServiceInformation }) =>
        ServiceInformation.ServiceDigitalIdentity.X509Certificates ?? [],
    )
    .map(({ val }) => val);
