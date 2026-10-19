import { HashAlgorithm, VerifyJwtCallback } from "@pagopa/io-wallet-utils";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { JAdESError } from "../../errors";
import { verifyJAdESSignature } from "../verify-jades-signature";
import { JAdESHeader, zJAdESHeader } from "../z-jades";

const certificate = Buffer.from("signer").toString("base64");
const digest = createHash("sha256")
  .update(Buffer.from("signer"))
  .digest("base64url");

const header: JAdESHeader = {
  alg: "ES256",
  iat: 1791849600,
  typ: "jwt",
  x5c: [certificate],
};

function options(overrides: Partial<JAdESHeader> = {}) {
  return {
    callbacks: {
      hash: vi.fn((data: Uint8Array, alg: HashAlgorithm) =>
        createHash(alg.replace("-", "")).update(data).digest(),
      ),
      verifyJwt: vi.fn(
        (): ReturnType<VerifyJwtCallback> => ({
          signerJwk: { kty: "EC" },
          verified: true,
        }),
      ),
    },
    compact: "a.b.c",
    header: { ...header, ...overrides },
    payload: {},
  };
}

describe("zJAdESHeader", () => {
  it("accepts a JAdES B-B header", () => {
    expect(zJAdESHeader.safeParse(header).success).toBe(true);
  });

  it("normalizes the short x5t#o digest algorithms", () => {
    const parsed = zJAdESHeader.parse({
      ...header,
      "x5t#o": { digAlg: "S256", digVal: digest },
    });
    expect(parsed["x5t#o"]?.digAlg).toBe(HashAlgorithm.Sha256);
  });

  it.each([
    ["alg none", { alg: "none" }],
    ["a symmetric alg", { alg: "HS256" }],
    ["sigD", { sigD: {} }],
    ["b64", { b64: false }],
    ["sigT", { sigT: "2026-10-13T00:00:00Z" }],
    ["no iat", { iat: undefined }],
    ["an empty x5c", { x5c: [] }],
    ["an empty crit", { crit: [] }],
    ["an unsupported critical parameter", { crit: ["foo"] }],
  ])("rejects a header with %s", (_, claims) => {
    expect(zJAdESHeader.safeParse({ ...header, ...claims }).success).toBe(
      false,
    );
  });

  it("does not accept a correctly signed token declaring an unsupported critical extension", async () => {
    const signatureOnly = options();
    const parsed = zJAdESHeader.safeParse({
      ...header,
      crit: ["foo"],
      foo: "bar",
    });
    expect(parsed.success).toBe(false);
    expect(signatureOnly.callbacks.verifyJwt).not.toHaveBeenCalled();
  });
});

describe("verifyJAdESSignature", () => {
  it("verifies the signature with the first x5c certificate", async () => {
    const verifyOptions = options();
    await verifyJAdESSignature(verifyOptions);

    expect(verifyOptions.callbacks.verifyJwt).toHaveBeenCalledWith(
      { alg: "ES256", method: "x5c", x5c: [certificate] },
      expect.objectContaining({ compact: "a.b.c" }),
    );
  });

  it("accepts an x5t#o matching the signing certificate", async () => {
    await expect(
      verifyJAdESSignature(
        options({ "x5t#o": { digAlg: HashAlgorithm.Sha256, digVal: digest } }),
      ),
    ).resolves.toBeUndefined();
  });

  it("rejects an x5t#o not matching the signing certificate", async () => {
    const verifyOptions = options({
      "x5t#o": { digAlg: HashAlgorithm.Sha256, digVal: "AAAA" },
    });

    await expect(verifyJAdESSignature(verifyOptions)).rejects.toThrow(
      JAdESError,
    );
    expect(verifyOptions.callbacks.verifyJwt).not.toHaveBeenCalled();
  });

  it("rejects an invalid signature", async () => {
    const verifyOptions = options();
    verifyOptions.callbacks.verifyJwt.mockReturnValue({ verified: false });

    await expect(verifyJAdESSignature(verifyOptions)).rejects.toMatchObject({
      code: "JADES_SIGNATURE_VERIFICATION_FAILED",
      name: "JAdESError",
    });
  });
});
