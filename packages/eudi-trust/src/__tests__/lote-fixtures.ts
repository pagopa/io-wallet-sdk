import type { ParsedLoTE } from "../lote/fetch-and-validate-lote";
import type { LoTE, TrustedEntity } from "../lote/z-lote";

import { LOTE_TYPES, LoTEProfile } from "../lote/constants";

export function createTrustedEntity(options: {
  services: {
    certificates: string[];
    skis?: string[];
    status?: string;
    subjectNames?: string[];
    type: string;
  }[];
  tradeName?: string;
}): TrustedEntity {
  return {
    TrustedEntityInformation: {
      TEAddress: { TEElectronicAddress: [], TEPostalAddress: [] },
      TEName: [{ lang: "en", value: "Provider" }],
      ...(options.tradeName && {
        TETradeName: [{ lang: "en", value: options.tradeName }],
      }),
    },
    TrustedEntityServices: options.services.map(
      ({ certificates, skis, status, subjectNames, type }) => ({
        ServiceInformation: {
          ServiceDigitalIdentity: {
            X509Certificates: certificates.map((val) => ({ val })),
            ...(skis && { X509SKIs: skis }),
            ...(subjectNames && { X509SubjectNames: subjectNames }),
          },
          ServiceName: [{ lang: "en", value: "Service" }],
          ...(status && { ServiceStatus: status }),
          ServiceTypeIdentifier: type,
        },
      }),
    ),
  };
}

export function createLoTE(
  profile: LoTEProfile,
  entities: TrustedEntity[],
): LoTE {
  return {
    ListAndSchemeInformation: {
      ListIssueDateTime: "2026-10-01T00:00:00Z",
      LoTESequenceNumber: 1,
      LoTEType: LOTE_TYPES[profile],
      LoTEVersionIdentifier: 1,
      NextUpdate: "2027-01-01T00:00:00Z",
      SchemeOperatorName: [{ lang: "en", value: "European Commission" }],
    },
    TrustedEntitiesList: entities,
  };
}

export function createParsedLoTE(document: LoTE): ParsedLoTE {
  return {
    compact: "",
    document,
    header: {
      alg: "ES256",
      cty: "json",
      iat: 0,
      kid: "",
      typ: "jose",
      x5c: [""],
    },
  };
}
