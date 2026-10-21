import { describe, expect, it } from "vitest";

import { WRPAC } from "../../wrpac/z-wrpac";
import { WRP_ENTITLEMENT_OIDS, WRP_ENTITLEMENTS } from "../entitlements";
import { verifyWRPAuthorization } from "../verify-wrp-authorization";
import { zWRPRCPayload } from "../z-wrprc";
import eudiwPayload from "./fixtures/eudiw-wrprc-payload.json";

const wrprc = zWRPRCPayload.parse(eudiwPayload);

const wrpac: WRPAC = {
  policies: [],
  publicJwk: { crv: "P-256", kty: "EC", x: "x", y: "y" },
  subject: {
    commonName: "NiScy PID Issuer",
    countryName: "EU",
    organizationIdentifier: "NTREU-123456789",
    organizationName: "NiScy PID Issuer",
  },
  subjectAltNames: {
    emails: [],
    phoneNumbers: [],
    uris: ["https://issuer.eudiw.dev"],
  },
};

const pid = { format: "dc+sd-jwt", vct: "urn:eudi:pid:1" } as const;
const mdl = { doctype: "org.iso.18013.5.1.mDL", format: "mso_mdoc" } as const;

describe("verifyWRPAuthorization", () => {
  it("authorizes a Wallet-Relying Party with an expected entitlement", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["QEAA_PROVIDER", "PUB_EAA_PROVIDER"],
        wrpac,
        wrprc,
      }),
    ).not.toThrow();
  });

  it("rejects a WRPRC of another entity than the WRPAC", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["SERVICE_PROVIDER"],
        wrpac,
        wrprc: { ...wrprc, sub: "NTREU-987654321" },
      }),
    ).toThrow(expect.objectContaining({ code: "BINDING_FAILED" }));
  });

  it("rejects a WRPRC without the expected entitlements", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["SERVICE_PROVIDER"],
        wrpac,
        wrprc: { ...wrprc, entitlements: [WRP_ENTITLEMENTS.PID_PROVIDER] },
      }),
    ).toThrow(expect.objectContaining({ code: "WRONG_ENTITLEMENT" }));
  });

  it("accepts an entitlement in OID form", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["SERVICE_PROVIDER"],
        wrpac,
        wrprc: {
          ...wrprc,
          entitlements: [WRP_ENTITLEMENT_OIDS.SERVICE_PROVIDER],
        },
      }),
    ).not.toThrow();
  });

  it("authorizes registered SD-JWT VC and mdoc attestation types", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["PID_PROVIDER"],
        providedAttestations: [pid, mdl],
        wrpac,
        wrprc,
      }),
    ).not.toThrow();
  });

  it.each([
    [
      "an unregistered type",
      { format: "dc+sd-jwt", vct: "urn:eudi:unregistered:1" } as const,
    ],
    [
      "a registered type in another format",
      { doctype: "urn:eudi:pid:1", format: "mso_mdoc" } as const,
    ],
    [
      "a type differing only in case",
      { doctype: "ORG.ISO.18013.5.1.MDL", format: "mso_mdoc" } as const,
    ],
  ])("rejects %s", (_, attestation) => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["PID_PROVIDER"],
        providedAttestations: [pid, attestation],
        wrpac,
        wrprc,
      }),
    ).toThrow(
      expect.objectContaining({ code: "ATTESTATION_TYPE_NOT_REGISTERED" }),
    );
  });

  it("rejects provided attestations when the WRPRC registers none", () => {
    expect(() =>
      verifyWRPAuthorization({
        entitlements: ["PID_PROVIDER"],
        providedAttestations: [mdl],
        wrpac,
        wrprc: { ...wrprc, provides_attestations: undefined },
      }),
    ).toThrow(
      expect.objectContaining({ code: "ATTESTATION_TYPE_NOT_REGISTERED" }),
    );
  });
});
