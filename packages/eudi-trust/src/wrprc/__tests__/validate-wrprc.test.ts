import { zJwk } from "@pagopa/io-wallet-utils";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

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

const encode = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function signWRPRC({
  header = {},
  key = signerKeys.privateKey,
  payload = {},
}: {
  header?: Record<string, unknown>;
  key?: typeof signerKeys.privateKey;
  payload?: Record<string, unknown>;
} = {}) {
  const signingInput = `${encode({
    alg: "ES256",
    typ: "rc-wrp+jwt",
    x5c: ["wrprc-signer"],
    ...header,
  })}.${encode({
    exp: nowInSeconds + 3600,
    iat: nowInSeconds - 3600,
    sub: "LEIXG-529900T8BM49AURSDO55",
    ...payload,
  })}`;
  const signature = sign("sha256", Buffer.from(signingInput), {
    dsaEncoding: "ieee-p1363",
    key,
  }).toString("base64url");
  return `${signingInput}.${signature}`;
}

const issuance = "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance";
const revocation = "http://uri.etsi.org/19602/SvcType/WRPRC/Revocation";

function options(
  overrides: Partial<ValidateWRPRCOptions> = {},
): ValidateWRPRCOptions {
  return {
    callbacks: {
      getX509CertificateMetadata: () => ({ organizations: [] }),
      verifyJwt: (_, jwt) => {
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
      },
      verifyX509CertificateChain: vi.fn(
        ({ trustAnchor }) => trustAnchor === "ta",
      ),
    },
    jwt: signWRPRC(),
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
  ])("rejects a header with %s", async (_, header) => {
    await expect(
      validateWRPRC(options({ jwt: signWRPRC({ header }) })),
    ).rejects.toThrow();
  });

  it("rejects an invalid signature", async () => {
    await expect(
      validateWRPRC(options({ jwt: signWRPRC({ key: otherKeys.privateKey }) })),
    ).rejects.toMatchObject({
      code: "WRPRC_SIGNATURE_VERIFICATION_FAILED",
      name: "WRPRCError",
    });
  });

  it("rejects a chain not validated by the WRPRC Issuance Trust Anchors", async () => {
    const validateOptions = options();
    validateOptions.callbacks.verifyX509CertificateChain = ({ trustAnchor }) =>
      trustAnchor === "ta-revocation";

    await expect(validateWRPRC(validateOptions)).rejects.toMatchObject({
      code: "CERTIFICATE_CHAIN_INVALID",
    });
  });

  it.each([
    ["issued in the future", { iat: nowInSeconds + 60 }, "WRPRC_NOT_YET_VALID"],
    ["expired", { exp: nowInSeconds }, "WRPRC_EXPIRED"],
  ])("rejects a WRPRC %s", async (_, payload, code) => {
    await expect(
      validateWRPRC(options({ jwt: signWRPRC({ payload }) })),
    ).rejects.toMatchObject({ code, name: "WRPRCError" });
  });

  it("accepts a WRPRC without iat and exp", async () => {
    const jwt = signWRPRC({ payload: { exp: undefined, iat: undefined } });
    await expect(validateWRPRC(options({ jwt }))).resolves.toBeDefined();
  });
});
