import { describe, expect, it, vi } from "vitest";

import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import { validateSignSealCertificate } from "../validate-sign-seal-certificate";

const issuance = "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance";
const lote = createParsedLoTE(
  createLoTE(LoTEProfile.EUWalletProvidersList, [
    createTrustedEntity({
      services: [{ certificates: ["ta"], type: issuance }],
    }),
  ]),
);
const callbacks = {
  getX509CertificateMetadata: () => ({ organizations: [] }),
  verifyX509CertificateChain: vi.fn(() => true),
};

describe("validateSignSealCertificate", () => {
  it("validates a WIA Sign/Seal chain against the Wallet Providers LoTE", async () => {
    await expect(
      validateSignSealCertificate({
        callbacks,
        chain: ["wia-signer"],
        lote,
        profile: LoTEProfile.EUWalletProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).resolves.toBe("ta");
  });

  it("rejects a LoTE of another type than the one selected", async () => {
    await expect(
      validateSignSealCertificate({
        callbacks,
        chain: ["pid-signer"],
        lote,
        profile: LoTEProfile.EUPIDProvidersList,
        serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PID/Issuance",
      }),
    ).rejects.toMatchObject({ code: "UNEXPECTED_LoTE_TYPE" });
  });
});
