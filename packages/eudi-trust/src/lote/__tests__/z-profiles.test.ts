import { describe, expect, it } from "vitest";

import { createLoTE, createTrustedEntity } from "../../__tests__/lote-fixtures";
import { LoTEProfile, PUB_EAA_SERVICE_STATUS } from "../constants";
import { zPIDProvidersList, zPubEAAProvidersList } from "../z-profiles";

function createPubEAADocument(status?: string) {
  const lote = createLoTE(LoTEProfile.EUPubEAAProvidersList, [
    createTrustedEntity({
      services: [
        {
          certificates: ["ta"],
          status,
          type: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
        },
      ],
    }),
  ]);
  lote.ListAndSchemeInformation = {
    ...lote.ListAndSchemeInformation,
    HistoricalInformationPeriod: 65535,
    SchemeTerritory: "EU",
    SchemeTypeCommunityRules: [
      {
        lang: "en",
        uriValue:
          "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU",
      },
    ],
    StatusDeterminationApproach:
      "http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU",
  };
  const [entity] = lote.TrustedEntitiesList;
  if (entity) {
    entity.TrustedEntityInformation.TEInformationURI = [
      {
        lang: "en",
        uriValue:
          "http://uri.etsi.org/19602/ListOfTrustedEntities/PubEAAProvider/IT",
      },
    ];
  }
  return { LoTE: lote };
}

describe("zPubEAAProvidersList", () => {
  it.each(Object.values(PUB_EAA_SERVICE_STATUS))(
    "accepts the %s service status",
    (status) => {
      expect(
        zPubEAAProvidersList.safeParse(createPubEAADocument(status)).success,
      ).toBe(true);
    },
  );

  it.each([
    ["a missing", undefined],
    [
      "an unknown",
      "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/other",
    ],
  ])("rejects %s service status", (_, status) => {
    expect(
      zPubEAAProvidersList.safeParse(createPubEAADocument(status)).success,
    ).toBe(false);
  });
});

describe("zPIDProvidersList", () => {
  it("rejects a service status", () => {
    const document = createPubEAADocument(PUB_EAA_SERVICE_STATUS.notified);
    const result = zPIDProvidersList.safeParse(document);

    expect(result.error?.issues).toContainEqual(
      expect.objectContaining({ message: "ServiceStatus must not be present" }),
    );
  });
});
