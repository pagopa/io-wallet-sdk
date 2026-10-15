import { JwtVerificationError } from "@pagopa/io-wallet-utils";
import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { signJws, toJwk, verifyJwtWithJwk } from "../../__tests__/jws-fixtures";
import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import { ValidateWRPRCOptions, validateWRPRC } from "../validate-wrprc";

const signerKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const otherKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const now = new Date("2026-10-13T00:00:00Z");
const nowInSeconds = now.getTime() / 1000;

function signWRPRC({
  header = {},
  key = signerKeys.privateKey,
  payload = {},
}: {
  header?: Record<string, unknown>;
  key?: typeof signerKeys.privateKey;
  payload?: Record<string, unknown>;
} = {}) {
  return signJws(
    {
      alg: "ES256",
      iat: nowInSeconds - 3600,
      typ: "rc-wrp+jwt",
      x5c: ["wrprc-signer"],
      ...header,
    },
    {
      country: "IT",
      entitlements: ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
      exp: nowInSeconds + 3600,
      iat: nowInSeconds - 3600,
      name: "Online Shop",
      registry_uri: "https://wrp-register.example.it/api/v1/relying-parties/1",
      status: { status_list: { idx: 1, uri: "https://status.example.it/1" } },
      sub: "LEIXG-529900T8BM49AURSDO55",
      sub_ln: "Online Shop S.p.A.",
      ...payload,
    },
    key,
  );
}

const issuance = "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance";
const revocation = "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation";

function options(
  overrides: Partial<ValidateWRPRCOptions> = {},
): ValidateWRPRCOptions {
  return {
    callbacks: {
      getX509CertificateMetadata: () => ({
        organizations: [],
        publicJwk: toJwk(signerKeys.publicKey),
      }),
      hash: (data, alg) =>
        createHash(alg.replace("-", "")).update(data).digest(),
      verifyJwt: (signer, jwt) =>
        verifyJwtWithJwk(
          signer.method === "x5c"
            ? {
                alg: signer.alg,
                method: "jwk",
                publicJwk: toJwk(signerKeys.publicKey),
              }
            : signer,
          jwt,
        ),
      verifyX509CertificateChain: vi.fn(
        ({ trustAnchor }) => trustAnchor === "ta",
      ),
    },
    wrprcJwt: signWRPRC(),
    lote: createParsedLoTE(
      createLoTE(LoTEProfile.EUWRPRCProvidersList, [
        createTrustedEntity({
          services: [
            { certificates: ["ta-revocation"], type: revocation },
            { certificates: ["ta"], type: issuance },
          ],
        }),
      ]),
    ),
    now,
    ...overrides,
  };
}

describe("validateWRPRC", () => {
  it("validates a WRPRC against the Providers of WRPRC LoTE", async () => {
    const validateOptions = options();
    const wrprc = await validateWRPRC(validateOptions);

    expect(wrprc.trustAnchor).toBe("ta");
    expect(wrprc.payload.sub).toBe("LEIXG-529900T8BM49AURSDO55");
    expect(
      validateOptions.callbacks.verifyX509CertificateChain,
    ).toHaveBeenCalledWith({ chain: ["wrprc-signer"], now, trustAnchor: "ta" });
  });

  it.each([
    ["an unexpected typ", { typ: "jwt" }],
    ["no x5c", { x5c: undefined }],
    ["no iat", { iat: undefined }],
  ])("rejects a header with %s", async (_, header) => {
    await expect(
      validateWRPRC(options({ wrprcJwt: signWRPRC({ header }) })),
    ).rejects.toThrow();
  });

  it.each([
    ["alg none", { alg: "none" }],
    ["a symmetric alg", { alg: "HS256" }],
    ["sigD", { sigD: { mId: "x" } }],
    ["b64", { b64: false }],
    ["the legacy sigT", { sigT: "2026-10-13T00:00:00Z" }],
  ])("rejects a header with %s", async (_, header) => {
    await expect(
      validateWRPRC(options({ wrprcJwt: signWRPRC({ header }) })),
    ).rejects.toThrow();
  });

  it("accepts an x5t#o matching the signing certificate", async () => {
    const digVal = createHash("sha256")
      .update(Buffer.from("wrprc-signer", "base64"))
      .digest("base64url");
    const wrprcJwt = signWRPRC({
      header: { "x5t#o": { digAlg: "sha-256", digVal } },
    });

    await expect(validateWRPRC(options({ wrprcJwt }))).resolves.toBeDefined();
  });

  it("rejects an x5t#o not matching the signing certificate", async () => {
    const wrprcJwt = signWRPRC({
      header: { "x5t#o": { digAlg: "sha-256", digVal: "AAAA" } },
    });

    await expect(validateWRPRC(options({ wrprcJwt }))).rejects.toMatchObject({
      code: "JADES_X5T_O_MISMATCH",
    });
  });

  it("rejects an invalid signature", async () => {
    await expect(
      validateWRPRC(
        options({ wrprcJwt: signWRPRC({ key: otherKeys.privateKey }) }),
      ),
    ).rejects.toBeInstanceOf(JwtVerificationError);
  });

  it("accepts an x5c ending with the Trust Anchor", async () => {
    const validateOptions = options({
      wrprcJwt: signWRPRC({ header: { x5c: ["wrprc-signer", "ta"] } }),
    });

    await expect(validateWRPRC(validateOptions)).resolves.toMatchObject({
      trustAnchor: "ta",
    });
    expect(
      validateOptions.callbacks.verifyX509CertificateChain,
    ).toHaveBeenCalledWith({ chain: ["wrprc-signer"], now, trustAnchor: "ta" });
  });

  it("directly trusts a WRPRC signed with the listed certificate", async () => {
    const validateOptions = options({
      wrprcJwt: signWRPRC({ header: { x5c: ["ta"] } }),
    });

    await expect(validateWRPRC(validateOptions)).resolves.toMatchObject({
      trustAnchor: "ta",
    });
    expect(
      validateOptions.callbacks.verifyX509CertificateChain,
    ).not.toHaveBeenCalled();
  });

  it("rejects a chain not validated by the WRPRC Issuance Trust Anchors", async () => {
    const validateOptions = options();
    validateOptions.callbacks.verifyX509CertificateChain = ({ trustAnchor }) =>
      trustAnchor === "ta-revocation";

    await expect(validateWRPRC(validateOptions)).rejects.toMatchObject({
      code: "CERTIFICATE_CHAIN_INVALID",
    });
  });

  it("rejects a WRPRC issued in the future", async () => {
    const wrprcJwt = signWRPRC({ payload: { iat: nowInSeconds + 60 } });
    await expect(validateWRPRC(options({ wrprcJwt }))).rejects.toMatchObject({
      code: "WRPRC_NOT_YET_VALID",
      name: "WRPRCError",
    });
  });

  it.each([
    ["in the past", nowInSeconds - 1],
    ["equal to now", nowInSeconds],
  ])("rejects a WRPRC with exp %s", async (_, exp) => {
    const wrprcJwt = signWRPRC({ payload: { exp } });
    await expect(validateWRPRC(options({ wrprcJwt }))).rejects.toMatchObject({
      code: "WRPRC_EXPIRED",
      name: "WRPRCError",
    });
  });

  it("accepts a WRPRC without exp", async () => {
    const wrprcJwt = signWRPRC({ payload: { exp: undefined } });
    await expect(validateWRPRC(options({ wrprcJwt }))).resolves.toBeDefined();
  });
});
