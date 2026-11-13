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
    ["x5t#S256 as critical", { crit: ["x5t#S256"] }],
    ["an unprocessed JAdES critical parameter", { crit: ["sigPl"] }],
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

describe("signing certificate references", () => {
  const sha256 = { digAlg: HashAlgorithm.Sha256, digVal: digest };
  const wrong = { digAlg: HashAlgorithm.Sha256, digVal: "AAAA" };

  it("accepts a matching x5t#S256", async () => {
    await expect(
      verifyJAdESSignature(options({ "x5t#S256": digest })),
    ).resolves.toBeUndefined();
  });

  it("rejects a mismatching x5t#S256", async () => {
    const verifyOptions = options({ "x5t#S256": "AAAA" });
    await expect(verifyJAdESSignature(verifyOptions)).rejects.toMatchObject({
      code: "JADES_X5T_S256_MISMATCH",
    });
    expect(verifyOptions.callbacks.verifyJwt).not.toHaveBeenCalled();
  });

  it("accepts a sigX5ts whose first entry matches the signer certificate", async () => {
    await expect(
      verifyJAdESSignature(options({ sigX5ts: [sha256, wrong] })),
    ).resolves.toBeUndefined();
  });

  it("rejects a sigX5ts whose first entry does not match", async () => {
    await expect(
      verifyJAdESSignature(options({ sigX5ts: [wrong, sha256] })),
    ).rejects.toMatchObject({ code: "JADES_SIG_X5TS_MISMATCH" });
  });

  it("rejects a sigX5ts with fewer than two entries", () => {
    expect(
      zJAdESHeader.safeParse({ ...header, sigX5ts: [sha256] }).success,
    ).toBe(false);
  });

  it("rejects the SHA-1 x5t thumbprint", () => {
    expect(zJAdESHeader.safeParse({ ...header, x5t: "AAAA" }).success).toBe(
      false,
    );
  });

  it.each([
    ["iat", {}],
    ["sigX5ts", { sigX5ts: [sha256, wrong] }],
    ["x5t#o", { "x5t#o": sha256 }],
  ])("accepts %s as a critical parameter", async (name, extra) => {
    const headerWithCrit = { crit: [name], ...extra } as Partial<JAdESHeader>;
    expect(
      zJAdESHeader.safeParse({ ...header, ...headerWithCrit }).success,
    ).toBe(true);
    await expect(
      verifyJAdESSignature(options(headerWithCrit)),
    ).resolves.toBeUndefined();
  });

  it("rejects a critical parameter missing from the header", async () => {
    await expect(
      verifyJAdESSignature(options({ crit: ["x5t#o"] })),
    ).rejects.toMatchObject({ code: "JADES_CRIT_PARAMETER_MISSING" });
  });

  it("accepts a critical parameter present in the header", async () => {
    await expect(
      verifyJAdESSignature(options({ crit: ["x5t#o"], "x5t#o": sha256 })),
    ).resolves.toBeUndefined();
  });
});

describe("claimed signing time", () => {
  it("rejects an iat later than the validation time", async () => {
    const verifyOptions = {
      ...options(),
      now: new Date((header.iat - 1) * 1000),
    };
    await expect(verifyJAdESSignature(verifyOptions)).rejects.toMatchObject({
      code: "JADES_IAT_IN_FUTURE",
    });
    expect(verifyOptions.callbacks.verifyJwt).not.toHaveBeenCalled();
  });

  it("accepts an iat equal to the validation time", async () => {
    await expect(
      verifyJAdESSignature({
        ...options(),
        now: new Date(header.iat * 1000),
      }),
    ).resolves.toBeUndefined();
  });
});
