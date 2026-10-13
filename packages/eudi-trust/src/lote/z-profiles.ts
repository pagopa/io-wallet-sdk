/**
 * LoTE Profiles
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * @see https://acceptance.eidas.ec.europa.eu/efda/wallet/lists-of-trusted-entities/mdl-providers
 */

import type z from "zod";

import { LOTE_TYPES, PUB_EAA_SERVICE_STATUS } from "./constants";
import { LoTEDocument, zLoTEDocument } from "./z-lote";

const SIX_MONTHS_IN_MS = 6 * 31 * 24 * 60 * 60 * 1000;

interface listAndSchemeInformationRefinerOptions {
  historicalInformationPeriod?: number;
  loTEType: string;
  loTEVersionIdentifier: number;
  requireNoHistoricalInformationPeriod?: boolean;
  requireNoPointersToOtherLoTE?: boolean;
  schemeTerritory: string;
  schemeTypeCommunityRulesUri: string;
  statusDeterminationApproach: string;
}

const listAndSchemeInformationRefiner =
  ({
    historicalInformationPeriod,
    loTEType,
    loTEVersionIdentifier,
    requireNoHistoricalInformationPeriod,
    requireNoPointersToOtherLoTE,
    schemeTerritory,
    schemeTypeCommunityRulesUri,
    statusDeterminationApproach,
  }: listAndSchemeInformationRefinerOptions) =>
  ({ LoTE }: LoTEDocument, ctx: z.RefinementCtx<LoTEDocument>) => {
    const info = LoTE.ListAndSchemeInformation;
    const path = ["LoTE", "ListAndSchemeInformation"];

    if (info.LoTEType !== loTEType) {
      ctx.addIssue({
        code: "invalid_value",
        message: `LoTEType must be ${loTEType}`,
        path: [...path, "LoTEType"],
        values: [loTEType],
      });
    }

    if (info.LoTEVersionIdentifier !== loTEVersionIdentifier) {
      ctx.addIssue({
        code: "invalid_value",
        message: `LoTEVersionIdentifier must be ${loTEVersionIdentifier}`,
        path: [...path, "LoTEVersionIdentifier"],
        values: [loTEVersionIdentifier],
      });
    }

    if (info.StatusDeterminationApproach !== statusDeterminationApproach) {
      ctx.addIssue({
        code: "invalid_value",
        message: `StatusDeterminationApproach must be ${statusDeterminationApproach}`,
        path: [...path, "StatusDeterminationApproach"],
        values: [statusDeterminationApproach],
      });
    }

    if (info.SchemeTerritory !== schemeTerritory) {
      ctx.addIssue({
        code: "invalid_value",
        message: `SchemeTerritory must be ${schemeTerritory}`,
        path: [...path, "SchemeTerritory"],
        values: [schemeTerritory],
      });
    }

    if (
      info.SchemeTypeCommunityRules?.length !== 1 ||
      info.SchemeTypeCommunityRules[0]?.uriValue !== schemeTypeCommunityRulesUri
    ) {
      ctx.addIssue({
        code: "custom",
        message: `SchemeTypeCommunityRules must contain a single element with uriValue of ${schemeTypeCommunityRulesUri}`,
        path: [...path, "SchemeTypeCommunityRules"],
      });
    }

    if (
      requireNoHistoricalInformationPeriod &&
      typeof info.HistoricalInformationPeriod !== "undefined"
    ) {
      ctx.addIssue({
        code: "invalid_type",
        expected: "undefined",
        message: "HistoricalInformationPeriod must not be present",
        path: [...path, "HistoricalInformationPeriod"],
      });
    }

    if (
      historicalInformationPeriod !== undefined &&
      info.HistoricalInformationPeriod !== historicalInformationPeriod
    ) {
      ctx.addIssue({
        code: "invalid_value",
        message: `HistoricalInformationPeriod must be ${historicalInformationPeriod}`,
        path: [...path, "HistoricalInformationPeriod"],
        values: [historicalInformationPeriod],
      });
    }

    if (
      requireNoPointersToOtherLoTE &&
      typeof info.PointersToOtherLoTE !== "undefined"
    ) {
      ctx.addIssue({
        code: "invalid_type",
        expected: "undefined",
        message: "PointersToOtherLoTE must not be present",
        path: [...path, "PointersToOtherLoTE"],
      });
    }

    const listIssueDateTime = new Date(info.ListIssueDateTime).getTime();
    const nextUpdate = new Date(info.NextUpdate).getTime();

    if (nextUpdate - listIssueDateTime > SIX_MONTHS_IN_MS) {
      ctx.addIssue({
        code: "custom",
        message: "NextUpdate must be within 6 months of ListIssueDateTime",
        path: [...path, "NextUpdate"],
      });
    }
  };

interface trustedEntitiesListRefinerOptions {
  /** When set, `ServiceStatus` is required and must be one of these values; otherwise it must be absent. */
  allowedServiceStatuses?: string[];
  allowedServiceTypeIdentifiers: string[];
  informationUriPrefix?: string;
}

const trustedEntitiesListRefiner =
  ({
    allowedServiceStatuses,
    allowedServiceTypeIdentifiers,
    informationUriPrefix,
  }: trustedEntitiesListRefinerOptions) =>
  ({ LoTE }: LoTEDocument, ctx: z.RefinementCtx<LoTEDocument>) => {
    LoTE.TrustedEntitiesList?.forEach((entity, index) => {
      const trustedEntityPath = [
        "LoTE",
        "TrustedEntitiesList",
        index.toString(),
      ];

      if (informationUriPrefix) {
        const uri = entity.TrustedEntityInformation.TEInformationURI?.find(
          ({ uriValue }) => uriValue.startsWith(informationUriPrefix),
        );

        if (!uri) {
          ctx.addIssue({
            code: "custom",
            message: `Each TrustedEntityInformation.TEInformationURI must contain at least one URI starting with ${informationUriPrefix}`,
            path: [
              ...trustedEntityPath,
              "TrustedEntityInformation",
              "TEInformationURI",
            ],
          });
        } else {
          const rest = uri.uriValue.substring(informationUriPrefix.length);
          if (rest.length !== 2) {
            ctx.addIssue({
              code: "custom",
              message: `URI starting with ${informationUriPrefix} must be followed by a 2-letter country code`,
              path: [
                ...trustedEntityPath,
                "TrustedEntityInformation",
                "TEInformationURI",
              ],
            });
          }
        }
      }

      entity.TrustedEntityServices.forEach((service, serviceIndex) => {
        const entityServicePath = [
          ...trustedEntityPath,
          "TrustedEntityServices",
          serviceIndex.toString(),
        ];

        if (allowedServiceStatuses) {
          const status = service.ServiceInformation.ServiceStatus;
          if (!status || !allowedServiceStatuses.includes(status)) {
            ctx.addIssue({
              code: "invalid_value",
              message: `ServiceStatus must be one of the following: ${allowedServiceStatuses.join(", ")}`,
              path: [
                ...entityServicePath,
                "ServiceInformation",
                "ServiceStatus",
              ],
              values: allowedServiceStatuses,
            });
          }
        } else if (
          typeof service.ServiceInformation.ServiceStatus !== "undefined"
        ) {
          ctx.addIssue({
            code: "invalid_type",
            expected: "undefined",
            message: "ServiceStatus must not be present",
            path: [...entityServicePath, "ServiceInformation", "ServiceStatus"],
          });
        }

        if (
          !allowedServiceStatuses &&
          typeof service.ServiceInformation.StatusStartingTime !== "undefined"
        ) {
          ctx.addIssue({
            code: "invalid_type",
            expected: "undefined",
            message: "StatusStartingTime must not be present",
            path: [
              ...entityServicePath,
              "ServiceInformation",
              "StatusStartingTime",
            ],
          });
        }

        if (
          !service.ServiceInformation.ServiceTypeIdentifier ||
          !allowedServiceTypeIdentifiers.includes(
            service.ServiceInformation.ServiceTypeIdentifier,
          )
        ) {
          ctx.addIssue({
            code: "invalid_value",
            message: `ServiceTypeIdentifier must be one of the following: ${allowedServiceTypeIdentifiers.join(", ")}`,
            path: [
              ...entityServicePath,
              "ServiceInformation",
              "ServiceTypeIdentifier",
            ],
            values: allowedServiceTypeIdentifiers,
          });
        }
      });
    });
  };

// ETSI TS 119 602 D
export const zPIDProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.EUPIDProvidersList,
      loTEVersionIdentifier: 1,
      requireNoHistoricalInformationPeriod: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/PIDProviders/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/PID/Issuance",
        "http://uri.etsi.org/19602/SvcType/PID/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/",
    }),
  );

// ETSI TS 119 602 E
export const zWalletProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.EUWalletProvidersList,
      loTEVersionIdentifier: 1,
      requireNoHistoricalInformationPeriod: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
        "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/WalletProvider/",
    }),
  );

// ETSI TS 119 602 F
export const zWRPACProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.EUWRPACProvidersList,
      loTEVersionIdentifier: 1,
      requireNoHistoricalInformationPeriod: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
        "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/",
    }),
  );

// ETSI TS 119 602 G
export const zWRPRCProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.EUWRPRCProvidersList,
      loTEVersionIdentifier: 1,
      requireNoHistoricalInformationPeriod: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/WRPRCProvidersList/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/WRPRCrovidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
        "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPRCProvider/",
    }),
  );

export const zEAAProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.EUEAAProvidersList,
      loTEVersionIdentifier: 1,
      requireNoPointersToOtherLoTE: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/EAAProvidersList/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/EAAProvidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/EAA/Issuance",
        "http://uri.etsi.org/19602/SvcType/EAA/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/EAAProvider/",
    }),
  );

// ETSI TS 119 602 H
export const zPubEAAProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      historicalInformationPeriod: 65535,
      loTEType: LOTE_TYPES.EUPubEAAProvidersList,
      loTEVersionIdentifier: 1,
      requireNoPointersToOtherLoTE: true,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU",
      statusDeterminationApproach:
        "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceStatuses: Object.values(PUB_EAA_SERVICE_STATUS),
      allowedServiceTypeIdentifiers: [
        "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
        "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation",
      ],
      informationUriPrefix:
        "http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/",
    }),
  );

// mDL Providers List
export const zMDLProvidersList = zLoTEDocument
  .superRefine(
    listAndSchemeInformationRefiner({
      loTEType: LOTE_TYPES.mDLProvidersList,
      loTEVersionIdentifier: 1,
      schemeTerritory: "EU",
      schemeTypeCommunityRulesUri:
        "http://trust.ec.europa.eu/lists/mDL/schemerules",
      statusDeterminationApproach:
        "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListStatusDetn",
    }),
  )
  .superRefine(
    trustedEntitiesListRefiner({
      allowedServiceTypeIdentifiers: [
        "http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance",
        "http://trust.ec.europa.eu/lists/mDL/SvcType/Revocation",
      ],
    }),
  );
