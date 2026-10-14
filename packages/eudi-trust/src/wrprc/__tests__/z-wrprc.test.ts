import { describe, expect, it } from "vitest";

import { zWRPRCJwtHeader, zWRPRCPayload } from "../z-wrprc";
import eudiwPayload from "./fixtures/eudiw-wrprc-payload.json";

const iat = 1790947382;

const payload = {
  country: "IT",
  entitlements: ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
  iat,
  name: "Online Shop",
  registry_uri: "https://wrp-register.example.it/api/v1/relying-parties/1",
  status: { status_list: { idx: 1, uri: "https://status.example.it/1" } },
  sub: "LEIXG-529900T8BM49AURSDO55",
  sub_ln: "Online Shop S.p.A.",
};

const isValid = (value: unknown) => zWRPRCPayload.safeParse(value).success;

describe("zWRPRCPayload", () => {
  it("accepts the WRPRC of the EUDI Wallet reference issuer", () => {
    expect(isValid(eudiwPayload)).toBe(true);
  });

  it("accepts a minimal legal person WRPRC", () => {
    expect(isValid(payload)).toBe(true);
  });

  it("accepts a natural person WRPRC", () => {
    expect(
      isValid({
        ...payload,
        sub: "TINIT-RSSMRA80A01H501U",
        sub_fn: "Rossi",
        sub_gn: "Mario",
        sub_ln: undefined,
      }),
    ).toBe(true);
  });

  it.each([
    "name",
    "sub",
    "country",
    "registry_uri",
    "entitlements",
    "iat",
    "status",
  ])("rejects a WRPRC without %s", (claim) => {
    expect(isValid({ ...payload, [claim]: undefined })).toBe(false);
  });

  it("rejects a WRPRC without the legal or natural person name", () => {
    expect(isValid({ ...payload, sub_ln: undefined })).toBe(false);
  });

  it.each([
    "NTREU-123456789",
    "VATIT-12345678901",
    "NTRDE+HE-123456",
    "EI:SE-5567971433",
  ])("accepts the legal person identifier %s", (sub) => {
    expect(isValid({ ...payload, sub })).toBe(true);
  });

  it.each(["IT123456789", "TINIT-RSSMRA80A01H501U", "LEIXG529900"])(
    "rejects the legal person identifier %s",
    (sub) => {
      expect(isValid({ ...payload, sub })).toBe(false);
    },
  );

  it("accepts entitlements in OID form and sub-entitlements", () => {
    expect(
      isValid({
        ...payload,
        entitlements: [
          "0.4.0.19475.1.1",
          "https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi",
        ],
      }),
    ).toBe(true);
  });

  it.each([
    ["an unknown entitlement", ["https://example.com/Entitlement"]],
    [
      "only sub-entitlements",
      ["https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi"],
    ],
  ])("rejects %s", (_, entitlements) => {
    expect(isValid({ ...payload, entitlements })).toBe(false);
  });

  it("accepts an exp 12 months after iat", () => {
    const exp = new Date(iat * 1000);
    exp.setUTCMonth(exp.getUTCMonth() + 12);
    expect(isValid({ ...payload, exp: exp.getTime() / 1000 })).toBe(true);
  });

  it.each([
    ["before iat", iat - 1],
    ["more than 12 months after iat", iat + 366 * 24 * 3600],
  ])("rejects an exp %s", (_, exp) => {
    expect(isValid({ ...payload, exp })).toBe(false);
  });

  it("accepts an intermediary as defined in Table 10", () => {
    expect(
      isValid({
        ...payload,
        intermediary: {
          sname: "Verification Service",
          sub: "LEIXG-529900INTERMEDIARY01",
        },
      }),
    ).toBe(true);
  });

  it.each([
    [
      "a nested intermediary",
      {
        intermediary: {
          sub: {
            id: "LEIXG-529900INTERMEDIARY01",
            sname: "Verification Service",
          },
        },
      },
    ],
    [
      "a credential claim without path",
      { credentials: [{ claim: [{}], format: "dc+sd-jwt", meta: {} }] },
    ],
    [
      "a status without index",
      { status: { status_list: { uri: "https://status.example.it/1" } } },
    ],
    ["a non-URL registry_uri", { registry_uri: "registry" }],
  ])("rejects %s", (_, claims) => {
    expect(isValid({ ...payload, ...claims })).toBe(false);
  });
});

describe("zWRPRCJwtHeader", () => {
  const header = { alg: "ES256", iat, typ: "rc-wrp+jwt", x5c: ["certificate"] };

  it("accepts a JAdES WRPRC header", () => {
    expect(zWRPRCJwtHeader.safeParse(header).success).toBe(true);
  });

  it.each([
    ["without iat", { iat: undefined }],
    ["with an unexpected typ", { typ: "jwt" }],
    ["with an empty x5c", { x5c: [] }],
  ])("rejects a header %s", (_, claims) => {
    expect(zWRPRCJwtHeader.safeParse({ ...header, ...claims }).success).toBe(
      false,
    );
  });
});
