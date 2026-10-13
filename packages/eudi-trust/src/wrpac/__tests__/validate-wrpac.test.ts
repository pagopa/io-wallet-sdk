import { describe, expect, it, vi } from "vitest";

import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import { validateWRPAC } from "../validate-wrpac";

const now = new Date("2026-10-13T00:00:00Z");

describe("validateWRPAC", () => {
  it("validates the chain against the Providers of WRPAC LoTE", async () => {
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
    const verifyX509CertificateChain = vi.fn(() => true);

    await expect(
      validateWRPAC({
        callbacks: {
          getX509CertificateMetadata: () => ({ organizations: [] }),
          verifyX509CertificateChain,
        },
        chain: ["wrpac"],
        lote,
        now,
      }),
    ).resolves.toBe("ta");
    expect(verifyX509CertificateChain).toHaveBeenCalledTimes(1);
  });
});
