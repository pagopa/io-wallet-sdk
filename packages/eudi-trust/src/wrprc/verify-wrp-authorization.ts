import { AuthorizationError } from "../errors";
import { WRPAC } from "../wrpac/z-wrpac";
import {
  WRP_ENTITLEMENT_OIDS,
  WRP_ENTITLEMENTS,
  WRPEntitlement,
  WRPEntitlementKey,
} from "./entitlements";
import { WRPRCPayload } from "./z-wrprc";

const OID_BY_ENTITLEMENT = Object.entries(WRP_ENTITLEMENTS).reduce(
  (acc, [key, entitlement]) => ({
    ...acc,
    [entitlement]: WRP_ENTITLEMENT_OIDS[key as WRPEntitlementKey],
  }),
  {} as Record<WRPEntitlement, string>,
);

/** An attestation type, identified by its format and type. */
export type AttestationType =
  | { doctype: string; format: "mso_mdoc" }
  | { format: "dc+sd-jwt"; vct: string };

export interface VerifyWRPAuthorizationOptions {
  /**
   * The entitlements expected for the interaction: the WRPRC must include at least one,
   * e.g. `WRP_ENTITLEMENTS.SERVICE_PROVIDER` for a Relying Party or `WRP_ENTITLEMENTS.PID_PROVIDER` for a PID Provider.
   * The WRPRC may express them in URI or OID form.
   */
  entitlements: [WRPEntitlement, ...WRPEntitlement[]];
  /** The attestation types the WRPRC must all register in `provides_attestations`. */
  providedAttestations?: AttestationType[];
  /** The WRPAC that authenticated the Wallet-Relying Party, validated with `validateWRPAC`. */
  wrpac: WRPAC;
  /** The WRPRC of the Wallet-Relying Party, validated with `validateWRPRC`. */
  wrprc: WRPRCPayload;
}

/**
 * Verifies that a Wallet-Relying Party is authorized for an interaction, as per the
 * IT-Wallet Authorization Validation: the WRPRC must belong to the authenticated
 * Wallet-Relying Party, include one of the expected entitlements and register
 * the attestation types it provides.
 *
 * The WRPAC and the WRPRC must be validated beforehand.
 *
 * @throws {AuthorizationError} if the Wallet-Relying Party is not authorized.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#authorization-validation
 */
export function verifyWRPAuthorization(
  options: VerifyWRPAuthorizationOptions,
): void {
  const { entitlements, providedAttestations = [], wrpac, wrprc } = options;

  const identifier =
    wrpac.subject.organizationIdentifier ?? wrpac.subject.serialNumber;
  if (identifier !== wrprc.sub) {
    throw new AuthorizationError(
      `The WRPRC subject ${wrprc.sub} does not match the WRPAC subject ${identifier}`,
      { code: "BINDING_FAILED" },
    );
  }

  const isEntitled = entitlements.some(
    (entitlement) =>
      wrprc.entitlements.includes(entitlement) ||
      wrprc.entitlements.includes(OID_BY_ENTITLEMENT[entitlement]),
  );
  if (!isEntitled) {
    throw new AuthorizationError(
      `The WRPRC includes none of the entitlements ${entitlements.join(", ")}`,
      { code: "WRONG_ENTITLEMENT" },
    );
  }

  const unregistered = providedAttestations.filter(
    (attestation) =>
      !wrprc.provides_attestations?.some((registered) =>
        matchesAttestationType(registered, attestation),
      ),
  );
  if (unregistered.length > 0) {
    throw new AuthorizationError(
      `The WRPRC does not register the attestation types ${unregistered
        .map((attestation) => `${getType(attestation)} (${attestation.format})`)
        .join(", ")}`,
      { code: "ATTESTATION_TYPE_NOT_REGISTERED" },
    );
  }
}

const getType = (attestation: AttestationType) =>
  attestation.format === "mso_mdoc" ? attestation.doctype : attestation.vct;

/** Exact, case sensitive match on `vct_values` for SD-JWT VC and on `doctype_value` for mdoc (ETSI TS 119 475 Table 8). */
function matchesAttestationType(
  registered: NonNullable<WRPRCPayload["provides_attestations"]>[number],
  attestation: AttestationType,
): boolean {
  if (registered.format !== attestation.format) {
    return false;
  }

  if (attestation.format === "mso_mdoc") {
    return registered.meta.doctype_value === attestation.doctype;
  }

  const { vct_values } = registered.meta;
  return Array.isArray(vct_values) && vct_values.includes(attestation.vct);
}
