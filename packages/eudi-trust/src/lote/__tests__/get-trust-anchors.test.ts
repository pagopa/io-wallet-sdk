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

  describe("with identity information", () => {
    const identityLote = createLoTE(LoTEProfile.EUWRPACProvidersList, [
      createTrustedEntity({
        services: [
          {
            certificates: ["ta-1"],
            skis: ["YseURyi9D6IWIKeawkmURPEB08c="],
            subjectNames: ["CN=Issuer CA 1,O=Provider,C=IT"],
            type: issuance,
          },
        ],
        tradeName: "VATIT-00000000001",
      }),
      createTrustedEntity({
        services: [{ certificates: ["ta-2"], type: issuance }],
        tradeName: "VATIT-00000000002",
      }),
      createTrustedEntity({
        services: [
          {
            certificates: ["ta-3"],
            subjectNames: ["CN=Issuer CA 3,C=IT"],
            type: issuance,
          },
        ],
        tradeName: "VATIT-00000000003",
      }),
    ]);
    const options = {
      lote: identityLote,
      profile: LoTEProfile.EUWRPACProvidersList,
      serviceTypeIdentifier: issuance,
    };

    it("narrows the candidates by the Authority Key Identifier", () => {
      expect(
        getTrustAnchors({
          ...options,
          authorityKeyIdentifier:
            "62:C7:94:47:28:BD:0F:A2:16:20:A7:9A:C2:49:94:44:F1:01:D3:C7",
        }),
      ).toEqual(["ta-1"]);
    });

    it("narrows the candidates by the issuer name against X509SubjectNames", () => {
      expect(
        getTrustAnchors({
          ...options,
          issuerName: "c=IT, o=Provider, cn=Issuer CA 1",
        }),
      ).toEqual(["ta-1"]);
    });

    it("prefers the Authority Key Identifier to the issuer name", () => {
      expect(
        getTrustAnchors({
          ...options,
          authorityKeyIdentifier: "62c7944728bd0fa21620a79ac2499444f101d3c7",
          issuerName: "CN=Issuer CA 3,C=IT",
        }),
      ).toEqual(["ta-1"]);
    });

    it("does not fall back to a less specific criterion when the provided one matches nothing", () => {
      expect(
        getTrustAnchors({
          ...options,
          authorityKeyIdentifier: "00",
          issuerName: "CN=Issuer CA 3,C=IT",
          issuerOrganizationIdentifier: "VATIT-00000000002",
        }),
      ).toEqual([]);
    });
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
