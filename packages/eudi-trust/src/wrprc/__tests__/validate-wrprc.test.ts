import { JwtVerificationError } from "@pagopa/io-wallet-utils";
import { generateKeyPairSync } from "node:crypto";
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
      verifyJwt: verifyJwtWithJwk,
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
    ["no iat", { iat: undefined }],
  ])("rejects a header with %s", async (_, header) => {
    await expect(
      validateWRPRC(options({ jwt: signWRPRC({ header }) })),
    ).rejects.toThrow();
  });

  it("rejects an invalid signature", async () => {
    await expect(
      validateWRPRC(options({ jwt: signWRPRC({ key: otherKeys.privateKey }) })),
    ).rejects.toBeInstanceOf(JwtVerificationError);
  });

  it.each([
    [true, "rejects"],
    [false, "accepts"],
  ])(
    "with rejectTrustAnchorInChain %s, %s an x5c ending with the Trust Anchor",
    async (rejectTrustAnchorInChain, outcome) => {
      const jwt = signWRPRC({ header: { x5c: ["wrprc-signer", "ta"] } });
      const result = validateWRPRC(options({ jwt, rejectTrustAnchorInChain }));

      if (outcome === "accepts") {
        await expect(result).resolves.toMatchObject({ trustAnchor: "ta" });
      } else {
        await expect(result).rejects.toMatchObject({
          code: "TRUST_ANCHOR_IN_CHAIN",
        });
      }
    },
  );

  it("rejects a chain not validated by the WRPRC Issuance Trust Anchors", async () => {
    const validateOptions = options();
    validateOptions.callbacks.verifyX509CertificateChain = ({ trustAnchor }) =>
      trustAnchor === "ta-revocation";

    await expect(validateWRPRC(validateOptions)).rejects.toMatchObject({
      code: "CERTIFICATE_CHAIN_INVALID",
    });
  });

  it("rejects a WRPRC issued in the future", async () => {
    const jwt = signWRPRC({ payload: { iat: nowInSeconds + 60 } });
    await expect(validateWRPRC(options({ jwt }))).rejects.toMatchObject({
      code: "WRPRC_NOT_YET_VALID",
      name: "WRPRCError",
    });
  });

  it.each([
    ["in the past", nowInSeconds - 1],
    ["equal to now", nowInSeconds],
  ])("rejects a WRPRC with exp %s", async (_, exp) => {
    const jwt = signWRPRC({ payload: { exp } });
    await expect(validateWRPRC(options({ jwt }))).rejects.toMatchObject({
      code: "WRPRC_EXPIRED",
      name: "WRPRCError",
    });
  });

  it("accepts a WRPRC without exp", async () => {
    const jwt = signWRPRC({ payload: { exp: undefined } });
    await expect(validateWRPRC(options({ jwt }))).resolves.toBeDefined();
  });
});
