import { describe, expect, it } from "vitest";

import {
  HashAlgorithm,
  ValidationError,
  calculateJwkThumbprint,
} from "../index";

const expectedDigest = new Uint8Array([
  172, 193, 245, 131, 255, 251, 73, 191, 56, 232, 7, 77, 66, 13, 69, 185, 82,
  125, 252, 124, 242, 92, 241, 86, 189, 208, 242, 167, 201, 127, 35, 198,
]);

const hashCallback = (data: Uint8Array, alg: HashAlgorithm) => {
  expect(alg).toBe(HashAlgorithm.Sha256);
  expect(new TextDecoder().decode(data)).toBe(
    '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF4Z2Z1S6vS2nvrVfJZzv8UpzboVb8PQRsM","y":"x_FEzRu9Y_ZmG9M2T1bkSgkA5WZ2QGZ7Y6KYFqJ9WgI"}',
  );

  return expectedDigest;
};

describe("jwk utilities", () => {
  it("calculates the expected thumbprint for an EC JWK", async () => {
    await expect(
      calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback,
        jwk: {
          crv: "P-256",
          kty: "EC",
          x: "f83OJ3D2xF4Z2Z1S6vS2nvrVfJZzv8UpzboVb8PQRsM",
          y: "x_FEzRu9Y_ZmG9M2T1bkSgkA5WZ2QGZ7Y6KYFqJ9WgI",
        },
      }),
    ).resolves.toBe("rMH1g__7Sb846AdNQg1FuVJ9_HzyXPFWvdDyp8l_I8Y");
  });

  it("throws ValidationError for unsupported JWK shapes", async () => {
    await expect(
      calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback,
        jwk: {
          crv: "P-256",
          kty: "EC",
          x: "missing-y",
        },
      }),
    ).rejects.toThrow(ValidationError);
  });
});
