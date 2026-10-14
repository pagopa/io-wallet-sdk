import { ValidationError } from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { wrpacMetadata } from "../../__tests__/certificate-fixtures";
import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import { X509CertificateMetadata } from "../../x509/types";
import { validateWRPAC } from "../validate-wrpac";

const now = new Date("2026-10-13T00:00:00Z");
const issuance = "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance";
const revocation = "http://uri.etsi.org/19602/SvcType/WRPAC/Revocation";

const lote = createParsedLoTE(
  createLoTE(LoTEProfile.EUWRPACProvidersList, [
    createTrustedEntity({
      services: [
        { certificates: ["ta-revocation"], type: revocation },
        { certificates: ["ta"], type: issuance },
      ],
    }),
  ]),
);

const validate = (metadata: X509CertificateMetadata) => {
  const verifyX509CertificateChain = vi.fn(() => true);
  return {
    result: validateWRPAC({
      callbacks: {
        getX509CertificateMetadata: () => metadata,
        verifyX509CertificateChain,
      },
      chain: ["wrpac"],
      lote,
      now,
    }),
    verifyX509CertificateChain,
  };
};

describe("validateWRPAC", () => {
  it("validates the chain against the Providers of WRPAC LoTE", async () => {
    const { result, verifyX509CertificateChain } = validate(wrpacMetadata);

    await expect(result).resolves.toBe("ta");
    expect(verifyX509CertificateChain).toHaveBeenCalledTimes(1);
  });

  it("rejects a WRPAC without a WRPAC policy", async () => {
    const { result } = validate({ ...wrpacMetadata, policies: [] });

    await expect(result).rejects.toBeInstanceOf(ValidationError);
  });
});
