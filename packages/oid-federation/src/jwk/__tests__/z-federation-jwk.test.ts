import { describe, expect, it } from "vitest";

import { itWalletEntityStatementClaimsSchema } from "../../entityStatement/itWalletEntityStatementClaims";
import { zFederationJwkSet } from "../z-federation-jwk";

const jwkWithoutKid = {
  crv: "P-256",
  kty: "EC",
  x: "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
  y: "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
};

describe("zFederationJwkSet", () => {
  it("accepts keys that carry a kid", () => {
    expect(
      zFederationJwkSet.safeParse({
        keys: [{ ...jwkWithoutKid, kid: "key-1" }],
      }).success,
    ).toBe(true);
  });

  it("rejects keys without a kid", () => {
    expect(zFederationJwkSet.safeParse({ keys: [jwkWithoutKid] }).success).toBe(
      false,
    );
  });

  it("rejects entity statements whose jwks contain a key without a kid", () => {
    const claims = (key: Record<string, string>) => ({
      exp: 1_900_000_000,
      iat: 1_800_000_000,
      iss: "https://trust-anchor.example.it",
      jwks: { keys: [key] },
      sub: "https://rp.example.it",
    });

    expect(
      itWalletEntityStatementClaimsSchema.safeParse(
        claims({ ...jwkWithoutKid, kid: "key-1" }),
      ).success,
    ).toBe(true);
    expect(
      itWalletEntityStatementClaimsSchema.safeParse(claims(jwkWithoutKid))
        .success,
    ).toBe(false);
  });
});
