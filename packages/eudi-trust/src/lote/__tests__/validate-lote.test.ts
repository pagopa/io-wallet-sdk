import { HashAlgorithm, zJwk } from "@pagopa/io-wallet-utils";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { X509CertificateMetadata } from "../../x509/types";
import { LOTE_TYPES, LoTEProfile } from "../constants";
import {
  ValidateLoTEOptions,
  fetchAndValidateLoTE,
  validateLoTE,
} from "../fetch-and-validate-lote";

const signerKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const otherKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signerCertificate = Buffer.from("signer-certificate").toString("base64");

const now = new Date("2026-10-13T00:00:00Z");

const document = {
  LoTE: {
    ListAndSchemeInformation: {
      ListIssueDateTime: "2026-10-01T00:00:00Z",
      LoTESequenceNumber: 1,
      LoTEType: LOTE_TYPES.EUPIDProvidersList,
      LoTEVersionIdentifier: 1,
      NextUpdate: "2027-01-01T00:00:00Z",
      SchemeOperatorName: [{ lang: "en", value: "European Commission" }],
      SchemeTerritory: "EU",
      SchemeTypeCommunityRules: [
        {
          lang: "en",
          uriValue: "http://uri.etsi.org/19602/PIDProviders/schemerules/EU",
        },
      ],
      StatusDeterminationApproach:
        "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
    },
    TrustedEntitiesList: [],
  },
};

const encode = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function signLoTE({
  header = {},
  key = signerKeys.privateKey,
}: {
  header?: Record<string, unknown>;
  key?: typeof signerKeys.privateKey;
} = {}) {
  const signingInput = `${encode({
    alg: "ES256",
    cty: "json",
    iat: 1791849600,
    kid: "signer",
    typ: "jose",
    x5c: [signerCertificate],
    ...header,
  })}.${encode(document)}`;
  const signature = sign("sha256", Buffer.from(signingInput), {
    dsaEncoding: "ieee-p1363",
    key,
  }).toString("base64url");
  return `${signingInput}.${signature}`;
}

const metadata: X509CertificateMetadata = {
  country: "EU",
  organizations: ["European Commission"],
  publicJwk: zJwk.parse(signerKeys.publicKey.export({ format: "jwk" })),
};

function options(
  overrides: Partial<ValidateLoTEOptions> = {},
): ValidateLoTEOptions {
  return {
    callbacks: {
      getX509CertificateMetadata: () => metadata,
      hash: (data, alg) =>
        createHash(alg.replace("-", "")).update(data).digest(),
      verifyJwt: vi.fn((_, jwt) => {
        const [header, payload, signature = ""] = jwt.compact.split(".");
        const verified = verify(
          "sha256",
          Buffer.from(`${header}.${payload}`),
          { dsaEncoding: "ieee-p1363", key: signerKeys.publicKey },
          Buffer.from(signature, "base64url"),
        );
        const signerJwk = zJwk.parse(
          signerKeys.publicKey.export({ format: "jwk" }),
        );
        return verified ? { signerJwk, verified } : { verified };
      }),
    },
    jwt: signLoTE(),
    now,
    profile: LoTEProfile.EUPIDProvidersList,
    trustedCertificates: [signerCertificate],
    ...overrides,
  };
}

const x5tO = (digest: string) => ({
  "x5t#o": { digAlg: HashAlgorithm.Sha512, digVal: digest },
});

const signerCertificateSha512 = createHash("sha512")
  .update(Buffer.from(signerCertificate, "base64"))
  .digest("base64url");

describe("validateLoTE", () => {
  it("authenticates a LoTE signed by a trusted certificate", async () => {
    const validateOptions = options();
    const lote = await validateLoTE(validateOptions);

    expect(lote.document).toEqual(document.LoTE);
    expect(validateOptions.callbacks.verifyJwt).toHaveBeenCalledWith(
      { alg: "ES256", method: "x5c", x5c: [signerCertificate] },
      expect.objectContaining({ compact: validateOptions.jwt }),
    );
  });

  it("accepts an x5t#o matching the signer certificate", async () => {
    const jwt = signLoTE({ header: x5tO(signerCertificateSha512) });
    await expect(validateLoTE(options({ jwt }))).resolves.toBeDefined();
  });

  it("accepts a signer certificate valid at the validation time", async () => {
    const validateOptions = options();
    validateOptions.callbacks.getX509CertificateMetadata = () => ({
      ...metadata,
      notAfter: new Date("2027-01-01T00:00:00Z"),
      notBefore: new Date("2026-01-01T00:00:00Z"),
    });
    await expect(validateLoTE(validateOptions)).resolves.toBeDefined();
  });

  it.each([
    ["alg none", { alg: "none" }],
    ["symmetric alg", { alg: "HS256" }],
    ["missing iat", { iat: undefined }],
    ["legacy sigT", { sigT: "2026-10-01T00:00:00Z" }],
    [
      "detached payload",
      { sigD: { mId: "http://uri.etsi.org/19182/ObjectIdByURI", pars: [] } },
    ],
    ["unencoded payload", { b64: false }],
    ["empty x5c", { x5c: [] }],
  ])("rejects a JAdES header with %s", async (_, header) => {
    await expect(
      validateLoTE(options({ jwt: signLoTE({ header }) })),
    ).rejects.toThrow();
  });

  it("rejects an x5t#o not matching the signer certificate", async () => {
    const jwt = signLoTE({ header: x5tO("AAAA") });
    await expect(validateLoTE(options({ jwt }))).rejects.toMatchObject({
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
      name: "LoTEError",
    });
  });

  it("rejects an invalid signature", async () => {
    const jwt = signLoTE({ key: otherKeys.privateKey });
    await expect(validateLoTE(options({ jwt }))).rejects.toMatchObject({
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
      name: "LoTEError",
    });
  });

  it.each([
    // ["a mismatching country", { ...metadata, country: "IT" }], // ETSI SPEC-DEVIATION
    ["a mismatching organization", { ...metadata, organizations: ["Other"] }],
    [
      "notBefore in the future",
      { ...metadata, notBefore: new Date("2026-11-01") },
    ],
    ["notAfter in the past", { ...metadata, notAfter: new Date("2026-10-01") }],
  ])("rejects a signer certificate with %s", async (_, m) => {
    const validateOptions = options();
    validateOptions.callbacks.getX509CertificateMetadata = () => m;
    await expect(validateLoTE(validateOptions)).rejects.toMatchObject({
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
      name: "LoTEError",
    });
  });

  it("rejects a signer certificate not trusted by the OJEU", async () => {
    await expect(
      validateLoTE(options({ trustedCertificates: ["other"] })),
    ).rejects.toMatchObject({
      code: "PIVOT_n_SIGNER_CERT_NOT_AUTHENTICATED_BY_OJEU",
      name: "LoTEError",
    });
  });

  it("rejects an expired LoTE", async () => {
    await expect(
      validateLoTE(options({ now: new Date("2027-01-01T00:00:00Z") })),
    ).rejects.toMatchObject({ code: "LoTE_EXPIRED", name: "LoTEError" });
  });
});

describe("fetchAndValidateLoTE", () => {
  it("fetches and authenticates the LoTE", async () => {
    const { callbacks, jwt, ...rest } = options();
    const fetch = vi.fn(
      async () =>
        new Response(jwt, {
          headers: { "Content-Type": "application/jose" },
        }),
    );

    const lote = await fetchAndValidateLoTE({
      ...rest,
      callbacks: { ...callbacks, fetch },
      ojeuUrl: "https://eur-lex.europa.eu/ojeu",
      url: "https://example.com/lote",
    });

    expect(lote.compact).toBe(jwt);
    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/lote",
      expect.anything(),
    );
  });
});
