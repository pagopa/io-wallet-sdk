import { describe, expect, it, vi } from "vitest";

import { ClientAttestationError } from "../../errors";
import { calculateDpopJwkThumbprint } from "../jwk-thumbprint";

describe("calculateDpopJwkThumbprint", () => {
  it("throws a clear error when the JWK key type is not supported", () => {
    const hash = vi.fn();

    expect(() =>
      calculateDpopJwkThumbprint({
        callbacks: { hash },
        dpopJwkPublic: {
          crv: "Ed25519",
          kty: "OKP",
          x: "test-x-value",
        },
      }),
    ).toThrow(ClientAttestationError);

    expect(() =>
      calculateDpopJwkThumbprint({
        callbacks: { hash },
        dpopJwkPublic: {
          crv: "Ed25519",
          kty: "OKP",
          x: "test-x-value",
        },
      }),
    ).toThrow(
      'Unsupported JWK key type "OKP" for thumbprint computation. Supported types: RSA, EC.',
    );
  });
});
