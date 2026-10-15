import { describe, expect, it, vi } from "vitest";

import { certificateMetadata } from "../../__tests__/certificate-fixtures";
import {
  createLoTE,
  createParsedLoTE,
  createTrustedEntity,
} from "../../__tests__/lote-fixtures";
import { LoTEProfile } from "../../lote/constants";
import {
  validateCertificateChain,
  validateLoTECertificateChain,
} from "../validate-certificate-chain";

const now = new Date("2026-10-13T00:00:00Z");

const acceptOnly = (trustedAnchor: string) =>
  vi.fn(
    ({ trustAnchor }: { trustAnchor: string }) => trustAnchor === trustedAnchor,
  );

describe("validateCertificateChain", () => {
  it("returns the first candidate Trust Anchor validating the chain", async () => {
    const verifyX509CertificateChain = acceptOnly("ta-2");

    await expect(
      validateCertificateChain({
        callbacks: { verifyX509CertificateChain },
        chain: ["leaf", "intermediate"],
        now,
        trustAnchors: ["ta-1", "ta-2"],
      }),
    ).resolves.toBe("ta-2");
    expect(verifyX509CertificateChain).toHaveBeenCalledWith({
      chain: ["leaf", "intermediate"],
      now,
      trustAnchor: "ta-1",
    });
  });

  it("treats a throwing callback as a failed candidate", async () => {
    const verifyX509CertificateChain = vi
      .fn()
      .mockRejectedValueOnce(new Error("invalid path"))
      .mockResolvedValueOnce(true);

    await expect(
      validateCertificateChain({
        callbacks: { verifyX509CertificateChain },
        chain: ["leaf"],
        trustAnchors: ["ta-1", "ta-2"],
      }),
    ).resolves.toBe("ta-2");
  });

  it.each([
    ["no candidate Trust Anchor", [], "TRUST_ANCHOR_NOT_FOUND"],
    [
      "no candidate validating the chain",
      ["ta-1"],
      "CERTIFICATE_CHAIN_INVALID",
    ],
  ] as const)("rejects %s", async (_, trustAnchors, code) => {
    await expect(
      validateCertificateChain({
        callbacks: { verifyX509CertificateChain: acceptOnly("ta") },
        chain: ["leaf"],
        trustAnchors: [...trustAnchors],
      }),
    ).rejects.toMatchObject({ code, name: "CertificateChainError" });
  });

  it("strips a trailing Trust Anchor before validating the chain", async () => {
    const verifyX509CertificateChain = acceptOnly("ta");

    await expect(
      validateCertificateChain({
        callbacks: { verifyX509CertificateChain },
        chain: ["leaf", "intermediate", "ta"],
        now,
        trustAnchors: ["ta"],
      }),
    ).resolves.toBe("ta");
    expect(verifyX509CertificateChain).toHaveBeenCalledWith({
      chain: ["leaf", "intermediate"],
      now,
      trustAnchor: "ta",
    });
  });

  it("recognizes a trailing Trust Anchor regardless of the base64 encoding", async () => {
    const verifyX509CertificateChain = acceptOnly("a+/b");

    await validateCertificateChain({
      callbacks: { verifyX509CertificateChain },
      chain: ["leaf", "a-_b\n=="],
      now,
      trustAnchors: ["a+/b"],
    });
    expect(verifyX509CertificateChain).toHaveBeenCalledWith({
      chain: ["leaf"],
      now,
      trustAnchor: "a+/b",
    });
  });

  it("directly trusts a chain made of a Trust Anchor alone", async () => {
    const verifyX509CertificateChain = acceptOnly("ta");

    await expect(
      validateCertificateChain({
        callbacks: { verifyX509CertificateChain },
        chain: ["ta"],
        trustAnchors: ["other", "ta"],
      }),
    ).resolves.toBe("ta");
    expect(verifyX509CertificateChain).not.toHaveBeenCalled();
  });
});

describe("validateLoTECertificateChain", () => {
  const issuance = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
  const lote = createParsedLoTE(
    createLoTE(LoTEProfile.EUPIDProvidersList, [
      createTrustedEntity({
        services: [{ certificates: ["ta-1"], type: issuance }],
        tradeName: "VATIT-00000000001",
      }),
      createTrustedEntity({
        services: [{ certificates: ["ta-2"], type: issuance }],
        tradeName: "VATIT-00000000002",
      }),
    ]),
  );

  it("narrows the candidates by the issuer of the last certificate", async () => {
    const getX509CertificateMetadata = vi.fn(() => ({
      ...certificateMetadata,
      issuerOrganizationIdentifier: "VATIT-00000000002",
      organizations: [],
    }));
    const verifyX509CertificateChain = vi.fn(() => true);

    await expect(
      validateLoTECertificateChain({
        callbacks: { getX509CertificateMetadata, verifyX509CertificateChain },
        chain: ["leaf", "intermediate"],
        lote,
        profile: LoTEProfile.EUPIDProvidersList,
        serviceTypeIdentifier: issuance,
      }),
    ).resolves.toBe("ta-2");
    expect(getX509CertificateMetadata).toHaveBeenCalledWith("intermediate");
    expect(verifyX509CertificateChain).toHaveBeenCalledTimes(1);
  });
});
