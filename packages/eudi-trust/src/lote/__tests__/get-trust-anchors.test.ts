import { describe, expect, it } from "vitest";

import { createLoTE, createTrustedEntity } from "../../__tests__/lote-fixtures";
import { LoTEProfile, PUB_EAA_SERVICE_STATUS } from "../constants";
import { getTrustAnchors } from "../get-trust-anchors";

const issuance = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance";
const revocation = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation";

const lote = createLoTE(LoTEProfile.EUWRPACProvidersList, [
  createTrustedEntity({
    services: [
      { certificates: ["ta-1"], type: issuance },
      { certificates: ["ta-1-revocation"], type: revocation },
    ],
    tradeName: "VATIT-00000000001",
  }),
  createTrustedEntity({
    services: [{ certificates: ["ta-2", "ta-3"], type: issuance }],
    tradeName: "VATIT-00000000002",
  }),
]);

describe("getTrustAnchors", () => {
  it("returns the Trust Anchors of the requested service type only", () => {
    const options = { lote, profile: LoTEProfile.EUWRPACProvidersList };

    expect(
      getTrustAnchors({ ...options, serviceTypeIdentifier: issuance }),
    ).toEqual(["ta-1", "ta-2", "ta-3"]);
    expect(
      getTrustAnchors({ ...options, serviceTypeIdentifier: revocation }),
    ).toEqual(["ta-1-revocation"]);
  });

  it("skips withdrawn services", () => {
    const issuance = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance";
    const pubEAALote = createLoTE(LoTEProfile.EUPubEAAProvidersList, [
      createTrustedEntity({
        services: [
          {
            certificates: ["notified"],
            status: PUB_EAA_SERVICE_STATUS.notified,
            type: issuance,
          },
          {
            certificates: ["withdrawn"],
            status: PUB_EAA_SERVICE_STATUS.withdrawn,
            type: issuance,
          },
        ],
      }),
    ]);

    expect(
      getTrustAnchors({
        lote: pubEAALote,
        profile: LoTEProfile.EUPubEAAProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).toEqual(["notified"]);
  });

  it("narrows the candidates by the issuer organization identifier", () => {
    expect(
      getTrustAnchors({
        issuerOrganizationIdentifier: "VATIT-00000000002",
        lote,
        profile: LoTEProfile.EUWRPACProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).toEqual(["ta-2", "ta-3"]);
  });

  it("returns no candidates when no trade name matches", () => {
    expect(
      getTrustAnchors({
        issuerOrganizationIdentifier: "VATIT-99999999999",
        lote,
        profile: LoTEProfile.EUWRPACProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).toEqual([]);
  });

  it("returns no Trust Anchors for a LoTE without trusted entities", () => {
    const empty = { ...lote, TrustedEntitiesList: undefined };

    expect(
      getTrustAnchors({
        lote: empty,
        profile: LoTEProfile.EUWRPACProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).toEqual([]);
  });

  it("rejects a LoTE of another profile", () => {
    expect(() =>
      getTrustAnchors({
        lote,
        profile: LoTEProfile.EUWRPRCProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).toThrow(expect.objectContaining({ code: "UNEXPECTED_LoTE_TYPE" }));
  });
});
