import {
  type CallbackContext,
  HashAlgorithm,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  type Jwk,
  calculateJwkThumbprint,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { BaseAuthorizationServerMetadata } from "../../authorization-server-metadata";

import { verifyClientAttestationPopJwt } from "../client-attestation-pop";
import { verifyClientAttestation } from "../verify-client-attestation";
import { verifyWalletAttestationJwt } from "../wallet-attestation";

vi.mock("../wallet-attestation", () => ({
  verifyWalletAttestationJwt: vi.fn(),
}));
vi.mock("../client-attestation-pop", () => ({
  verifyClientAttestationPopJwt: vi.fn(),
}));

const jwk: Jwk = { crv: "P-256", kty: "EC", x: "test-x", y: "test-y" };

const callbacks: Pick<CallbackContext, "hash" | "verifyJwt"> = {
  hash: vi.fn(async (data) =>
    new TextEncoder().encode(
      `hashed-${typeof data === "string" ? data : new TextDecoder().decode(data)}`,
    ),
  ),
  verifyJwt: vi.fn(),
};

const verify = (itWalletSpecsVersion: ItWalletSpecsVersion, clientId: string) =>
  verifyClientAttestation({
    authorizationServerMetadata: {
      issuer: "https://auth.example.com",
    } as BaseAuthorizationServerMetadata,
    callbacks,
    clientAttestation: {
      clientAttestationPopJwt: "pop.jwt.value",
      walletAttestationJwt: "wia.jwt.value",
    },
    config: new IoWalletSdkConfig({ itWalletSpecsVersion }),
    requestClientId: clientId,
  });

describe("verifyClientAttestation client_id check", () => {
  beforeEach(() => {
    vi.mocked(verifyWalletAttestationJwt).mockResolvedValue({
      payload: { cnf: { jwk }, sub: "https://wallet.example.it" },
    } as Awaited<ReturnType<typeof verifyWalletAttestationJwt>>);
    vi.mocked(verifyClientAttestationPopJwt).mockResolvedValue(
      {} as Awaited<ReturnType<typeof verifyClientAttestationPopJwt>>,
    );
  });

  it("accepts a V1_5 client_id equal to the cnf.jwk thumbprint", async () => {
    const thumbprint = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk,
    });

    await expect(
      verify(ItWalletSpecsVersion.V1_5, thumbprint),
    ).resolves.toBeDefined();
  });

  it("rejects a V1_5 client_id equal to the attestation sub", async () => {
    await expect(
      verify(ItWalletSpecsVersion.V1_5, "https://wallet.example.it"),
    ).rejects.toThrow(/does not match the client id/);
  });

  it("keeps comparing client_id with sub before V1_5", async () => {
    await expect(
      verify(ItWalletSpecsVersion.V1_4, "https://wallet.example.it"),
    ).resolves.toBeDefined();
  });
});
