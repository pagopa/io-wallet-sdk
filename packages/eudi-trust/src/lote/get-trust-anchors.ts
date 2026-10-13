import { LoTEError } from "../errors";
import { LOTE_TYPES, LoTEProfile } from "./constants";
import { LoTE } from "./z-lote";

export interface GetTrustAnchorsOptions {
  /**
   * `organizationIdentifier` of the issuer of the last certificate of the chain.
   * When it matches the `TETradeName` of some entities, only those are considered.
   */
  issuerOrganizationIdentifier?: string;
  /** A LoTE authenticated with `validateLoTE`. */
  lote: LoTE;
  profile: LoTEProfile;
  /** E.g. `http://uri.etsi.org/19602/SvcType/WRPAC/Issuance` (ETSI TS 119 602 Annexes D-I). */
  serviceTypeIdentifier: string;
}

/**
 * Retrieve the candidate Trust Anchor certificates (DER encoded in base64) from the
 * `ServiceDigitalIdentity` of the services of type `serviceTypeIdentifier` (ETSI TS 119 602
 * clause 6.6.3), following the "Retrieve the Trust Anchor" step of the
 * IT-Wallet EUDIW Authentication.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-authentication
 */
export function getTrustAnchors(options: GetTrustAnchorsOptions): string[] {
  const { issuerOrganizationIdentifier, lote, profile } = options;

  if (lote.ListAndSchemeInformation.LoTEType !== LOTE_TYPES[profile]) {
    throw new LoTEError(`LoTE is not of type ${LOTE_TYPES[profile]}`, {
      code: "UNEXPECTED_LoTE_TYPE",
    });
  }

  // ETSI EN 319 412-1 clause 5.1.4 and ETSI TS 119 602 Annex F, Table F.2:
  // TETradeName carries the registration identifier of the entity.
  const matchingEntities = issuerOrganizationIdentifier
    ? lote.TrustedEntitiesList.filter((entity) =>
        entity.TrustedEntityInformation.TETradeName?.some(
          ({ value }) => value === issuerOrganizationIdentifier,
        ),
      )
    : [];
  const entities =
    matchingEntities.length > 0 ? matchingEntities : lote.TrustedEntitiesList;

  return entities
    .flatMap((entity) => entity.TrustedEntityServices)
    .filter(
      ({ ServiceInformation }) =>
        ServiceInformation.ServiceTypeIdentifier ===
        options.serviceTypeIdentifier,
    )
    .flatMap(
      ({ ServiceInformation }) =>
        ServiceInformation.ServiceDigitalIdentity.X509Certificates ?? [],
    )
    .map(({ val }) => val);
}
