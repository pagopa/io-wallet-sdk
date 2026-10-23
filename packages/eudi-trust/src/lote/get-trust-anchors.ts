import { LoTEError } from "../errors";
import {
  keyIdentifierToBase64,
  normalizeDistinguishedName,
} from "../x509/certificate";
import { LOTE_TYPES, LoTEProfile, PUB_EAA_SERVICE_STATUS } from "./constants";
import { LoTE, TrustedEntity, TrustedEntityService } from "./z-lote";

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
 * Only active services contribute. Each service is matched against the issuer of the last
 * certificate of the chain using the most specific identity it publishes: the Authority Key
 * Identifier against its `X509SKIs`, otherwise the issuer name against its `X509SubjectNames`,
 * otherwise the issuer organization identifier against the `TETradeName` of its entity.
 * A service is a candidate when it matches, or when none of these can be compared.
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

  const expectedSki =
    authorityKeyIdentifier && keyIdentifierToBase64(authorityKeyIdentifier);
  const expectedName = issuerName && normalizeDistinguishedName(issuerName);

  const matchesIssuer = (
    entity: TrustedEntity,
    { ServiceInformation }: TrustedEntityService,
  ) => {
    const { X509SKIs, X509SubjectNames } =
      ServiceInformation.ServiceDigitalIdentity;

    if (expectedSki && X509SKIs?.length) {
      return X509SKIs.includes(expectedSki);
    }

    if (expectedName && X509SubjectNames?.length) {
      return X509SubjectNames.some(
        (name) => normalizeDistinguishedName(name) === expectedName,
      );
    }

    // `TETradeName` carries the registration identifier of the entity
    // (ETSI EN 319 412-1 clause 5.1.4, ETSI TS 119 602 Annex F)
    if (issuerOrganizationIdentifier) {
      return (
        entity.TrustedEntityInformation.TETradeName?.some(
          ({ value }) => value === issuerOrganizationIdentifier,
        ) ?? false
      );
    }

    return true;
  };

  return getServiceCertificates(
    lote.TrustedEntitiesList.flatMap((entity) =>
      entity.TrustedEntityServices.filter(
        (service) =>
          isRequestedServiceType(service) && matchesIssuer(entity, service),
      ),
    ),
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
