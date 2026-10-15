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
    wrprcJwt: signWRPRC(),
    ...overrides,
  };
}

describe("validateWRPRC", () => {
  it("validates a WRPRC against the Providers of WRPRC LoTE", async () => {
    const validateOptions = options();
    const validated = await validateWRPRC(validateOptions);

    expect(validated.trustAnchor).toBe("ta");
    expect(validated.wrprc.sub).toBe("LEIXG-529900T8BM49AURSDO55");
    expect(
      validateOptions.callbacks.verifyX509CertificateChain,
    ).toHaveBeenCalledWith({ chain: ["wrprc-signer"], now, trustAnchor: "ta" });
  });

  it("rejects an unexpected typ", async () => {
    const wrprcJwt = signWRPRC({ header: { typ: "jwt" } });
    await expect(validateWRPRC(options({ wrprcJwt }))).rejects.toThrow();
  });

  it("rejects an invalid signature", async () => {
    await expect(
      validateWRPRC(
        options({ wrprcJwt: signWRPRC({ key: otherKeys.privateKey }) }),
      ),
    ).rejects.toMatchObject({
      code: "JADES_SIGNATURE_VERIFICATION_FAILED",
      name: "JAdESError",
    });
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

  it("rejects an expired WRPRC", async () => {
    const wrprcJwt = signWRPRC({ payload: { exp: nowInSeconds - 1 } });
    await expect(validateWRPRC(options({ wrprcJwt }))).rejects.toMatchObject({
      code: "JADES_SIGNATURE_VERIFICATION_FAILED",
      name: "JAdESError",
    });
  });

  it("accepts a WRPRC without exp", async () => {
    const wrprcJwt = signWRPRC({ payload: { exp: undefined } });
    await expect(validateWRPRC(options({ wrprcJwt }))).resolves.toBeDefined();
  });
});
