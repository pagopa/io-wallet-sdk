import { JwtVerificationError, ValidationError } from "@pagopa/io-wallet-utils";
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { wrpacMetadata } from "../../__tests__/certificate-fixtures";
import { signJws, toJwk, verifyJwtWithJwk } from "../../__tests__/jws-fixtures";
import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import { X509CertificateMetadata } from "../../x509/types";
import {
  EvaluateJwsTrustOptions,
  evaluateJwsTrust,
} from "../evaluate-jws-trust";

const signerKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const otherKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const now = new Date("2026-10-13T00:00:00Z");
const nowInSeconds = now.getTime() / 1000;
const issuance = "http://uri.etsi.org/19602/SvcType/PID/Issuance";

const signPID = ({
  header = {},
  key = signerKeys.privateKey,
  payload = {},
}: {
  header?: Record<string, unknown>;
  key?: typeof signerKeys.privateKey;
  payload?: Record<string, unknown>;
} = {}) =>
  signJws(
    { typ: "dc+sd-jwt", x5c: ["pid-signer", "pid-intermediate"], ...header },
    { exp: nowInSeconds + 3600, iss: "https://pid.example", ...payload },
    key,
  );

function options(
  overrides: Partial<EvaluateJwsTrustOptions> = {},
): EvaluateJwsTrustOptions {
  return {
    callbacks: {
      getX509CertificateMetadata: vi.fn(() => ({
        organizations: [],
        publicJwk: toJwk(signerKeys.publicKey),
      })),
      verifyJwt: verifyJwtWithJwk,
      verifyX509CertificateChain: vi.fn(
        ({ trustAnchor }) => trustAnchor === "ta",
      ),
    },
    jwt: signPID(),
    lote: createParsedLoTE(
      createLoTE(LoTEProfile.EUPIDProvidersList, [
        createTrustedEntity({
          services: [{ certificates: ["ta"], type: issuance }],
        }),
      ]),
    ),
    now,
    profile: LoTEProfile.EUPIDProvidersList,
    serviceTypeIdentifier: issuance,
    ...overrides,
  };
}

const wrpacIssuance = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance";

function wrpacOptions(
  metadata: X509CertificateMetadata,
): EvaluateJwsTrustOptions {
  return options({
    callbacks: {
      ...options().callbacks,
      getX509CertificateMetadata: () => ({
        ...metadata,
        organizations: [],
        publicJwk: toJwk(signerKeys.publicKey),
      }),
    },
    lote: createParsedLoTE(
      createLoTE(LoTEProfile.EUWRPACProvidersList, [
        createTrustedEntity({
          services: [{ certificates: ["ta"], type: wrpacIssuance }],
        }),
      ]),
    ),
    profile: LoTEProfile.EUWRPACProvidersList,
    serviceTypeIdentifier: wrpacIssuance,
  });
}

describe("evaluateJwsTrust", () => {
  it("checks the WRPAC content when the LoTE is a Providers of WRPAC LoTE", async () => {
    await expect(
      evaluateJwsTrust(wrpacOptions(wrpacMetadata)),
    ).resolves.toMatchObject({ trustAnchor: "ta" });
    await expect(
      evaluateJwsTrust(wrpacOptions({ ...wrpacMetadata, policies: [] })),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("does not check the WRPAC content for other LoTEs", async () => {
    await expect(evaluateJwsTrust(options())).resolves.toBeDefined();
  });

  it("verifies the signature with the leaf public key, then the chain", async () => {
    const verifyOptions = options();
    const jws = await evaluateJwsTrust(verifyOptions);

    expect(
      verifyOptions.callbacks.getX509CertificateMetadata,
    ).toHaveBeenCalledWith("pid-signer");
    expect(jws.signer.publicJwk).toEqual(toJwk(signerKeys.publicKey));
    expect(jws.trustAnchor).toBe("ta");
    expect(jws.payload.iss).toBe("https://pid.example");
    expect(
      verifyOptions.callbacks.verifyX509CertificateChain,
    ).toHaveBeenCalledWith({
      chain: ["pid-signer", "pid-intermediate"],
      now,
      trustAnchor: "ta",
    });
  });

  it("verifies only the issuer-signed JWT of an SD-JWT", async () => {
    const jwt = signPID();
    const jws = await evaluateJwsTrust(
      options({ jwt: `${jwt}~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIk1hcmlvIl0~` }),
    );

    expect(jws.compact).toBe(jwt);
  });

  it("rejects an invalid signature before validating the chain", async () => {
    const verifyOptions = options({
      jwt: signPID({ key: otherKeys.privateKey }),
    });

    await expect(evaluateJwsTrust(verifyOptions)).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
    expect(
      verifyOptions.callbacks.verifyX509CertificateChain,
    ).not.toHaveBeenCalled();
  });

  it("rejects an expired jws", async () => {
    const jwt = signPID({ payload: { exp: nowInSeconds - 1 } });
    await expect(evaluateJwsTrust(options({ jwt }))).rejects.toBeInstanceOf(
      JwtVerificationError,
    );
  });

  it("rejects an jws without x5c", async () => {
    const jwt = signPID({ header: { x5c: undefined } });
    await expect(evaluateJwsTrust(options({ jwt }))).rejects.toThrow();
  });

  it("rejects a chain not validated by the LoTE Trust Anchors", async () => {
    const verifyOptions = options();
    verifyOptions.callbacks.verifyX509CertificateChain = () => false;

    await expect(evaluateJwsTrust(verifyOptions)).rejects.toMatchObject({
      code: "CERTIFICATE_CHAIN_INVALID",
    });
  });
});
