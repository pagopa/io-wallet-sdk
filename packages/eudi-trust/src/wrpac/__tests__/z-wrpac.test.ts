import { describe, expect, it } from "vitest";

import { wrpacMetadata } from "../../__tests__/certificate-fixtures";
import { WRPAC_POLICIES } from "../policies";
import { zWRPAC } from "../z-wrpac";

const isValid = (value: unknown) => zWRPAC.safeParse(value).success;

const naturalPersonWRPAC = {
  ...wrpacMetadata,
  policies: [{ cpsUris: [], oid: WRPAC_POLICIES.NCP_NATURAL }],
  subject: {
    commonName: "Mario Rossi",
    countryName: "IT",
    givenName: "Mario",
    serialNumber: "TINIT-RSSMRA80A01H501U",
    surname: "Rossi",
  },
};

describe("zWRPAC", () => {
  it("accepts the WRPAC of the EUDI Wallet reference issuer", () => {
    expect(isValid(wrpacMetadata)).toBe(true);
  });

  it("accepts a natural person WRPAC", () => {
    expect(isValid(naturalPersonWRPAC)).toBe(true);
  });

  it.each(["policies", "subject", "subjectAltNames"])(
    "rejects a WRPAC without %s",
    (field) => {
      expect(isValid({ ...wrpacMetadata, [field]: undefined })).toBe(false);
    },
  );

  it.each([
    ["a CA certificate", { isCA: true }],
    ["a keyUsage without digitalSignature", { keyUsage: ["keyCertSign"] }],
    ["no WRPAC policy", { policies: [{ cpsUris: [], oid: "1.2.3" }] }],
    [
      "both legal and natural person policies",
      {
        policies: [
          { cpsUris: [], oid: WRPAC_POLICIES.NCP_LEGAL },
          { cpsUris: [], oid: WRPAC_POLICIES.QCP_NATURAL },
        ],
      },
    ],
    [
      "no contact in the subjectAltNames",
      { subjectAltNames: { emails: [], phoneNumbers: [], uris: [] } },
    ],
  ])("rejects %s", (_, fields) => {
    expect(isValid({ ...wrpacMetadata, ...fields })).toBe(false);
  });

  it.each([
    ["commonName", { commonName: undefined }],
    ["countryName", { countryName: "Italy" }],
    ["organizationName", { organizationName: undefined }],
    ["organizationIdentifier", { organizationIdentifier: undefined }],
    ["organizationIdentifier format", { organizationIdentifier: "IT123" }],
  ])("rejects a legal person WRPAC with an invalid %s", (_, subject) => {
    expect(
      isValid({
        ...wrpacMetadata,
        subject: { ...wrpacMetadata.subject, ...subject },
      }),
    ).toBe(false);
  });

  it.each([
    ["givenName", { givenName: undefined }],
    ["surname", { surname: undefined }],
    ["serialNumber", { serialNumber: "NTREU-123456789" }],
  ])("rejects a natural person WRPAC with an invalid %s", (_, subject) => {
    expect(
      isValid({
        ...naturalPersonWRPAC,
        subject: { ...naturalPersonWRPAC.subject, ...subject },
      }),
    ).toBe(false);
  });

  it("accepts a WRPAC contact given only by email", () => {
    expect(
      isValid({
        ...wrpacMetadata,
        subjectAltNames: {
          emails: ["rp@example.it"],
          phoneNumbers: [],
          uris: [],
        },
      }),
    ).toBe(true);
  });
});
